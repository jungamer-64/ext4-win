//! Requestor-context capture for requests that cross the PASSIVE_LEVEL device queue.

use alloc::boxed::Box;
use core::{ffi::c_void, num::NonZeroUsize, ptr::NonNull};

#[cfg(not(test))]
use wdk_sys::NTSTATUS;
use wdk_sys::{PVOID, STATUS_SUCCESS};

use crate::kernel::ffi;
use crate::{
    kernel::status::{DriverError, DriverResult},
    memory,
    memory::DriverVec,
    security_descriptor::SecuritySelection,
    state::KernelFileObject,
};

use super::{
    ActiveIrp, DataIoKind, DirectoryControlMinorFunction, DispatchMajor,
    FileSystemControlMinorFunction, IrpBufferLength, IrpCompletion, QueryDirectoryStack,
    QueryEaStack, ReadStack, WriteStack,
};

/// Maximum self-relative security descriptor accepted from one untrusted requestor.
#[cfg(not(test))]
const SET_SECURITY_DESCRIPTOR_MAXIMUM: wdk_sys::ULONG = 128 * 1024;

/// Owned directory pattern captured before queue insertion.
#[derive(Debug)]
pub(crate) enum PreparedDirectoryPattern {
    /// No filename filter was supplied.
    All,
    /// Requestor-owned UTF-16 filename filter copied into nonpaged driver memory.
    Name(DriverVec<u16>),
}

/// Owned query-EA selection captured before queue insertion.
#[derive(Debug)]
pub(crate) enum PreparedEaSelection {
    /// Return every EA associated with the opened file.
    All,
    /// Requestor-owned FILE_GET_EA_INFORMATION bytes.
    Names(DriverVec<u8>),
    /// Return the entry at a caller-supplied one-based index.
    Index(super::EaEntryIndex),
}

/// Directory-control request whose meaningful auxiliary inputs are sealed before queue insertion.
#[derive(Debug)]
pub(crate) enum PreparedDirectoryControl {
    /// Query-directory request with an owned filename pattern.
    QueryDirectory(PreparedQueryDirectory),
    /// Standard directory-change notification.
    NotifyChangeDirectory,
}

/// Complete QueryDirectory payload sealed at queue entry.
#[derive(Debug)]
pub(crate) struct PreparedQueryDirectory {
    /// Scalar stack fields that remain valid with the pending IRP.
    stack: QueryDirectoryStack,
    /// Requestor-owned filename pattern.
    pattern: PreparedDirectoryPattern,
}

impl PreparedQueryDirectory {
    /// Returns the immutable scalar stack payload.
    pub(crate) const fn stack(&self) -> QueryDirectoryStack {
        self.stack
    }

    /// Borrows the captured filename pattern.
    pub(crate) fn pattern(&self) -> &PreparedDirectoryPattern {
        &self.pattern
    }
}

/// Complete QueryEa payload sealed at queue entry.
#[derive(Debug)]
pub(crate) struct PreparedQueryEa {
    /// Scalar stack fields that remain valid with the pending IRP.
    stack: QueryEaStack,
    /// Requestor-owned EA selection.
    selection: PreparedEaSelection,
}

/// Read parameters and system mapping captured before queue insertion.
#[derive(Debug)]
pub(crate) struct PreparedRead {
    /// Handle or paging origin sealed before the IRP can leave requestor context.
    kind: DataIoKind,
    /// Scalar read parameters copied from the requestor's stack location.
    stack: ReadStack,
    /// Exact system-mapped output range kept live by the pending IRP.
    output: CapturedReadOutput,
}

impl PreparedRead {
    /// Captures a read stack and its system-addressable output range.
    /// # Errors
    ///
    /// Returns a completion error when stack decoding or output mapping fails.
    fn capture(
        target: &ActiveIrp<'_>,
        stack: super::CurrentIrpStackLocation<'_>,
    ) -> Result<Self, IrpCompletion> {
        let kind = target.data_io_kind();
        let stack = stack.read().map_err(IrpCompletion::from_error)?;
        let output = CapturedReadOutput::capture(target, stack.length())?;
        Ok(Self {
            kind,
            stack,
            output,
        })
    }

    /// Returns the request origin sealed at capture.
    pub(crate) const fn kind(&self) -> DataIoKind {
        self.kind
    }

    /// Returns the immutable scalar read parameters.
    pub(crate) const fn stack(&self) -> ReadStack {
        self.stack
    }

    /// Returns the first output byte for transfer-alignment validation.
    pub(crate) const fn output_address(&self) -> Option<NonNull<u8>> {
        self.output.address()
    }

    /// Borrows the exact caller output range for the duration of active read execution.
    pub(crate) fn output_mut(&mut self) -> &mut [u8] {
        self.output.as_mut_slice()
    }
}

/// Non-empty system mapping retained by one pending data-transfer IRP.
#[derive(Debug)]
struct CapturedDataMapping {
    /// First mapped byte.
    address: NonNull<u8>,
    /// Exact non-zero mapped byte count.
    length: NonZeroUsize,
}

// SAFETY: The I/O Manager keeps the system buffer or locked MDL mapping valid until the owning IRP
// completes. Direction-specific ownership controls whether the mapping becomes a Rust slice or is
// consumed only through a native copy boundary.
unsafe impl Send for CapturedDataMapping {}

impl CapturedDataMapping {
    /// Binds one validated address to a non-empty IRP range.
    const fn new(address: NonNull<u8>, length: NonZeroUsize) -> Self {
        Self { address, length }
    }

    /// Returns the first mapped byte.
    const fn address(&self) -> NonNull<u8> {
        self.address
    }

    /// Returns the exact mapped byte count.
    const fn len(&self) -> usize {
        self.length.get()
    }
}

/// System-addressable read output whose validity is owned by the containing pending IRP.
#[derive(Debug)]
enum CapturedReadOutput {
    /// A zero-byte read has no output mapping.
    Empty,
    /// Non-empty I/O Manager buffer or MDL system mapping.
    Mapped(CapturedDataMapping),
}

impl CapturedReadOutput {
    /// Captures the output mapping without allowing a Rust reference to cross queue publication.
    /// # Errors
    ///
    /// Returns a completion error when a non-empty request has no valid system mapping.
    fn capture(target: &ActiveIrp<'_>, length: IrpBufferLength) -> Result<Self, IrpCompletion> {
        let Some(mapped_length) = NonZeroUsize::new(length.as_usize()) else {
            return Ok(Self::Empty);
        };
        let address = target
            .data_output_address(length)
            .map_err(IrpCompletion::from_error)?;
        Ok(Self::Mapped(CapturedDataMapping::new(
            address,
            mapped_length,
        )))
    }

    /// Returns the first mapped byte when this is a non-empty output.
    const fn address(&self) -> Option<NonNull<u8>> {
        match self {
            Self::Empty => None,
            Self::Mapped(mapping) => Some(mapping.address()),
        }
    }

    /// Borrows the complete captured output range.
    fn as_mut_slice(&mut self) -> &mut [u8] {
        match self {
            Self::Empty => &mut [],
            Self::Mapped(mapping) => unsafe {
                // SAFETY: Capture validated this exact non-empty mapping while the owning IRP was
                // live. `&mut self` proves unique actor access and the IRP cannot complete while
                // its `PendingIrpLease` is executing.
                core::slice::from_raw_parts_mut(mapping.address().as_ptr(), mapping.len())
            },
        }
    }
}

/// Write parameters and system mapping captured before queue insertion.
#[derive(Debug)]
pub(crate) struct PreparedWrite {
    /// Handle or paging origin sealed before the IRP can leave requestor context.
    kind: DataIoKind,
    /// Scalar write parameters copied from the requestor's stack location.
    stack: WriteStack,
    /// Exact system-mapped input range kept live by the pending IRP.
    input: CapturedWriteInput,
}

impl PreparedWrite {
    /// Captures a write stack and its system-addressable input range.
    /// # Errors
    ///
    /// Returns a completion error when stack decoding or input mapping fails.
    fn capture(
        target: &ActiveIrp<'_>,
        stack: super::CurrentIrpStackLocation<'_>,
    ) -> Result<Self, IrpCompletion> {
        let kind = target.data_io_kind();
        let stack = stack.write().map_err(IrpCompletion::from_error)?;
        let input = CapturedWriteInput::capture(target, stack.length())?;
        Ok(Self { kind, stack, input })
    }

    /// Returns the request origin sealed at capture.
    pub(crate) const fn kind(&self) -> DataIoKind {
        self.kind
    }

    /// Returns the immutable scalar write parameters.
    pub(crate) const fn stack(&self) -> WriteStack {
        self.stack
    }

    /// Returns the first input byte for transfer-alignment validation.
    pub(crate) const fn input_address(&self) -> Option<NonNull<u8>> {
        self.input.address()
    }

    /// Snapshots one checked caller-input window into driver-owned storage.
    /// # Errors
    ///
    /// Returns an invariant error when the selected range exceeds the captured write input or the
    /// native copy boundary rejects it.
    pub(crate) fn copy_window(&self, offset: usize, destination: &mut [u8]) -> DriverResult<()> {
        self.input.copy_window(offset, destination)
    }
}

/// System-addressable write input whose validity is owned by the containing pending IRP.
#[derive(Debug)]
enum CapturedWriteInput {
    /// A zero-byte write has no input mapping.
    Empty,
    /// Non-empty I/O Manager buffer or MDL system mapping.
    Mapped(CapturedDataMapping),
}

impl CapturedWriteInput {
    /// Captures the input mapping without allowing a Rust reference to cross queue publication.
    /// # Errors
    ///
    /// Returns a completion error when a non-empty request has no valid system mapping.
    fn capture(target: &ActiveIrp<'_>, length: IrpBufferLength) -> Result<Self, IrpCompletion> {
        let Some(mapped_length) = NonZeroUsize::new(length.as_usize()) else {
            return Ok(Self::Empty);
        };
        let address = target
            .data_input_address(length)
            .map_err(IrpCompletion::from_error)?;
        Ok(Self::Mapped(CapturedDataMapping::new(
            address,
            mapped_length,
        )))
    }

    /// Returns the first mapped byte when this is a non-empty input.
    const fn address(&self) -> Option<NonNull<u8>> {
        match self {
            Self::Empty => None,
            Self::Mapped(mapping) => Some(mapping.address()),
        }
    }

    /// Snapshots one checked range without admitting requestor memory into Rust's aliasing model.
    /// # Errors
    ///
    /// Returns an invariant error when `offset..offset + destination.len()` exceeds the captured
    /// input or the native copy boundary rejects the range.
    fn copy_window(&self, offset: usize, destination: &mut [u8]) -> DriverResult<()> {
        match self {
            Self::Empty if offset == 0 && destination.is_empty() => Ok(()),
            Self::Empty => Err(DriverError::InternalInvariantViolation),
            Self::Mapped(mapping) => {
                let end = offset
                    .checked_add(destination.len())
                    .ok_or(DriverError::InternalInvariantViolation)?;
                if end > mapping.len() {
                    return Err(DriverError::InternalInvariantViolation);
                }
                if destination.is_empty() {
                    return Ok(());
                }
                let source_length = wdk_sys::ULONG::try_from(mapping.len())
                    .map_err(|_| DriverError::InternalInvariantViolation)?;
                let source_offset = wdk_sys::ULONG::try_from(offset)
                    .map_err(|_| DriverError::InternalInvariantViolation)?;
                let destination_length = wdk_sys::ULONG::try_from(destination.len())
                    .map_err(|_| DriverError::InternalInvariantViolation)?;
                let status = unsafe {
                    // SAFETY: The pending IRP retains `mapping`; checked arithmetic proves the
                    // selected source window is in range, and `destination` is a distinct,
                    // initialized driver-owned mutable range for the native copy.
                    ffi::ext4win_copy_write_input_window(
                        mapping.address().as_ptr().cast(),
                        source_length,
                        source_offset,
                        destination.as_mut_ptr().cast(),
                        destination_length,
                    )
                };
                if status < STATUS_SUCCESS {
                    return Err(DriverError::InternalInvariantViolation);
                }
                Ok(())
            }
        }
    }
}

impl PreparedQueryEa {
    /// Returns the immutable scalar stack payload.
    pub(crate) const fn stack(&self) -> QueryEaStack {
        self.stack
    }

    /// Borrows the captured EA selection.
    pub(crate) fn selection(&self) -> &PreparedEaSelection {
        &self.selection
    }
}

/// Requestor auxiliary bytes copied into nonpaged native memory.
#[derive(Debug)]
struct CapturedRequestorInput {
    /// First byte of the native allocation.
    address: NonNull<u8>,
    /// Exact copied byte count.
    length: NonZeroUsize,
}

// SAFETY: The immutable nonpaged allocation is uniquely owned and crosses threads only inside the
// typed device-mailbox payload whose publication requires `Send`.
unsafe impl Send for CapturedRequestorInput {}

impl CapturedRequestorInput {
    /// Captures a bounded EA name list before an IRP is queued.
    /// # Errors
    ///
    /// Returns a completion preserving native capture failure or allocation validation failure.
    fn capture_ea_name_list(
        target: &ActiveIrp<'_>,
        source: NonNull<c_void>,
        length: super::IrpBufferLength,
    ) -> Result<Self, IrpCompletion> {
        #[cfg(not(test))]
        {
            let length = wdk_sys::ULONG::try_from(length.as_usize())
                .map_err(|_| IrpCompletion::from_error(DriverError::InvalidParameter))?;
            let requestor_mode = unsafe {
                // SAFETY: Dispatch retains the received IRP until capture returns.
                target.irp.as_ref().RequestorMode
            };
            let mut snapshot = core::ptr::null_mut();
            let mut captured_length = 0;
            let status = unsafe {
                // SAFETY: The native boundary probes/copies only the bounded requestor range.
                ffi::ext4win_capture_ea_name_list(
                    source.as_ptr(),
                    length,
                    requestor_mode,
                    core::ptr::addr_of_mut!(snapshot),
                    core::ptr::addr_of_mut!(captured_length),
                )
            };
            ensure_native_success(status)?;
            if captured_length != length {
                if !snapshot.is_null() {
                    unsafe {
                        // SAFETY: Native capture transferred this allocation to the constructor.
                        ffi::ext4win_release_captured_requestor_input(snapshot);
                    }
                }
                return Err(IrpCompletion::from_error(
                    DriverError::InternalInvariantViolation,
                ));
            }
            let Some(address) = NonNull::new(snapshot.cast::<u8>()) else {
                return Err(IrpCompletion::from_error(
                    DriverError::InternalInvariantViolation,
                ));
            };
            let Some(length) =
                NonZeroUsize::new(usize::try_from(captured_length).map_err(|_| {
                    IrpCompletion::from_error(DriverError::InternalInvariantViolation)
                })?)
            else {
                unsafe {
                    // SAFETY: Native capture returned a null-length violation with ownership
                    // transferred to this failed constructor.
                    ffi::ext4win_release_captured_requestor_input(address.as_ptr().cast());
                }
                return Err(IrpCompletion::from_error(
                    DriverError::InternalInvariantViolation,
                ));
            };
            Ok(Self { address, length })
        }
        #[cfg(test)]
        {
            let _: &ActiveIrp<'_> = target;
            let _: NonNull<c_void> = source;
            let _: super::IrpBufferLength = length;
            Err(IrpCompletion::from_error(DriverError::InvalidDeviceRequest))
        }
    }

    /// Captures a query-directory filename pattern, returning `None` for an empty string.
    /// # Errors
    ///
    /// Returns a completion preserving native capture failure or allocation validation failure.
    fn capture_directory_pattern(
        target: &ActiveIrp<'_>,
        source: NonNull<wdk_sys::UNICODE_STRING>,
    ) -> Result<Option<Self>, IrpCompletion> {
        #[cfg(not(test))]
        {
            let _: &ActiveIrp<'_> = target;
            let mut snapshot = core::ptr::null_mut();
            let mut captured_length = 0;
            let status = unsafe {
                // SAFETY: The native boundary captures and validates the I/O-manager-owned string
                // header and payload under SEH protection.
                ffi::ext4win_capture_io_manager_directory_pattern(
                    source.as_ptr(),
                    core::ptr::addr_of_mut!(snapshot),
                    core::ptr::addr_of_mut!(captured_length),
                )
            };
            ensure_native_success(status)?;
            if captured_length == 0 {
                if !snapshot.is_null() {
                    unsafe {
                        // SAFETY: Native capture transferred this unexpected allocation to the
                        // constructor, which releases it before reporting the invariant failure.
                        ffi::ext4win_release_captured_requestor_input(snapshot);
                    }
                    return Err(IrpCompletion::from_error(
                        DriverError::InternalInvariantViolation,
                    ));
                }
                return Ok(None);
            }
            let Some(address) = NonNull::new(snapshot.cast::<u8>()) else {
                return Err(IrpCompletion::from_error(
                    DriverError::InternalInvariantViolation,
                ));
            };
            let Some(length) =
                NonZeroUsize::new(usize::try_from(captured_length).map_err(|_| {
                    IrpCompletion::from_error(DriverError::InternalInvariantViolation)
                })?)
            else {
                unsafe {
                    // SAFETY: Native capture transferred this allocation to the constructor.
                    ffi::ext4win_release_captured_requestor_input(address.as_ptr().cast());
                }
                return Err(IrpCompletion::from_error(
                    DriverError::InternalInvariantViolation,
                ));
            };
            Ok(Some(Self { address, length }))
        }
        #[cfg(test)]
        {
            let _: &ActiveIrp<'_> = target;
            let _: NonNull<wdk_sys::UNICODE_STRING> = source;
            Err(IrpCompletion::from_error(DriverError::InvalidDeviceRequest))
        }
    }

    /// Borrows the exact captured bytes.
    fn as_slice(&self) -> &[u8] {
        unsafe {
            // SAFETY: Native capture initialized exactly `length` bytes in this owned allocation.
            core::slice::from_raw_parts(self.address.as_ptr(), self.length.get())
        }
    }
}

impl Drop for CapturedRequestorInput {
    fn drop(&mut self) {
        #[cfg(not(test))]
        unsafe {
            // SAFETY: This value uniquely owns the native snapshot allocation.
            ffi::ext4win_release_captured_requestor_input(self.address.as_ptr().cast());
        }
    }
}

/// Request identity captured before the IRP enters the cancel-safe queue.
#[derive(Debug)]
pub(super) struct QueueContext {
    /// Complete typed request classification plus any requestor-context capture.
    prepared: PreparedRequest,
    /// Stable cleanup cancellation identity; no queued stack re-decode is required.
    cancellation_key: QueueCancellationKey,
}

/// Queue metadata ownership after dispatch selects allocation-free lifecycle requests or captured
/// requestor state.
#[derive(Debug)]
pub(super) enum QueueContextOwnership {
    /// Heap-owned request classification and requestor-context capture.
    Captured(Box<QueueContext>),
    /// Allocation-free cleanup barrier executed after earlier file requests.
    Cleanup,
    /// Allocation-free terminal FILE_OBJECT release executed after cleanup.
    Close,
}

impl QueueContextOwnership {
    /// Borrows the read contract captured before queue insertion.
    /// # Errors
    ///
    /// Returns an invariant error when this is not a captured read request.
    pub(super) fn read(&self) -> DriverResult<&PreparedRead> {
        match self {
            Self::Captured(context) => context.read(),
            Self::Cleanup | Self::Close => Err(DriverError::InternalInvariantViolation),
        }
    }

    /// Mutably borrows the read contract captured before queue insertion.
    /// # Errors
    ///
    /// Returns an invariant error when this is not a captured read request.
    pub(super) fn read_mut(&mut self) -> DriverResult<&mut PreparedRead> {
        match self {
            Self::Captured(context) => context.read_mut(),
            Self::Cleanup | Self::Close => Err(DriverError::InternalInvariantViolation),
        }
    }

    /// Borrows the write contract captured before queue insertion.
    /// # Errors
    ///
    /// Returns an invariant error when this is not a captured write request.
    pub(super) fn write(&self) -> DriverResult<&PreparedWrite> {
        match self {
            Self::Captured(context) => context.write(),
            Self::Cleanup | Self::Close => Err(DriverError::InternalInvariantViolation),
        }
    }

    /// Borrows the opaque query-security output target.
    /// # Errors
    ///
    /// Returns an invariant error when this is not captured query-security metadata.
    pub(super) fn query_security_parts(
        &mut self,
    ) -> DriverResult<(SecuritySelection, &mut CapturedQuerySecurityOutput)> {
        match self {
            Self::Captured(context) => context.query_security_parts(),
            Self::Cleanup | Self::Close => Err(DriverError::InternalInvariantViolation),
        }
    }

    /// Borrows the immutable set-security snapshot.
    /// # Errors
    ///
    /// Returns an invariant error when this is not captured set-security metadata.
    pub(super) fn set_security_parts(&self) -> DriverResult<(SecuritySelection, &[u8])> {
        match self {
            Self::Captured(context) => context.set_security_parts(),
            Self::Cleanup | Self::Close => Err(DriverError::InternalInvariantViolation),
        }
    }

    /// Borrows the complete QueryDirectory payload.
    /// # Errors
    ///
    /// Returns an invariant error when this is not captured query-directory metadata.
    pub(super) fn query_directory(&self) -> DriverResult<&PreparedQueryDirectory> {
        match self {
            Self::Captured(context) => context.query_directory(),
            Self::Cleanup | Self::Close => Err(DriverError::InternalInvariantViolation),
        }
    }

    /// Borrows the complete QueryEa payload.
    /// # Errors
    ///
    /// Returns an invariant error when this is not captured query-EA metadata.
    pub(super) fn query_ea(&self) -> DriverResult<&PreparedQueryEa> {
        match self {
            Self::Captured(context) => context.query_ea(),
            Self::Cleanup | Self::Close => Err(DriverError::InternalInvariantViolation),
        }
    }
}

impl QueueContext {
    /// Captures one queued request while dispatch still runs in the requestor's context.
    /// # Errors
    ///
    /// Returns a completion payload when stack classification, requestor-memory capture, or
    /// queue-context allocation fails.
    pub(super) fn capture(
        target: &ActiveIrp<'_>,
        major: DispatchMajor,
    ) -> Result<QueueContextOwnership, IrpCompletion> {
        let stack = target.current_stack().map_err(IrpCompletion::from_error)?;
        match major {
            DispatchMajor::Cleanup => {
                stack.file_object().map_err(IrpCompletion::from_error)?;
                return Ok(QueueContextOwnership::Cleanup);
            }
            DispatchMajor::Close => {
                stack.file_object().map_err(IrpCompletion::from_error)?;
                return Ok(QueueContextOwnership::Close);
            }
            _ => {}
        }
        let (prepared, cancellation_key) = PreparedRequest::capture(target, stack, major)?;
        memory::boxed_try_with(|| {
            Ok(Self {
                prepared,
                cancellation_key,
            })
        })
        .map(QueueContextOwnership::Captured)
        .map_err(IrpCompletion::from_error)
    }

    /// Builds a create context for tests of terminal ownership independent of native capture.
    /// # Errors
    ///
    /// Returns an allocation error when the context cannot be boxed.
    #[cfg(test)]
    pub(super) fn for_test_create() -> DriverResult<Box<Self>> {
        memory::boxed_try_with(|| {
            Ok(Self {
                prepared: PreparedRequest::Create,
                cancellation_key: QueueCancellationKey::Device,
            })
        })
    }

    /// Returns whether this queued request belongs to a cleanup cancellation identity.
    pub(super) fn matches_cancellation_context(&self, context: PVOID) -> bool {
        context.is_null() || self.cancellation_key.matches(context)
    }

    /// Returns whether CLEANUP may cancel this not-yet-started ordinary request.
    pub(super) fn cleanup_cancel_eligible(&self) -> bool {
        !matches!(
            &self.prepared,
            PreparedRequest::Read(read) if read.kind() == DataIoKind::Paging
        ) && !matches!(
            &self.prepared,
            PreparedRequest::Write(write) if write.kind() == DataIoKind::Paging
        ) && !matches!(&self.prepared, PreparedRequest::FlushBuffers)
    }

    /// Returns the request variant sealed before the IRP entered the queue.
    pub(super) const fn prepared(&self) -> &PreparedRequest {
        &self.prepared
    }

    /// Borrows the read contract captured before queue insertion.
    /// # Errors
    ///
    /// Returns an invariant error when this context is not a read request.
    pub(super) fn read(&self) -> DriverResult<&PreparedRead> {
        match &self.prepared {
            PreparedRequest::Read(request) => Ok(request),
            _ => Err(DriverError::InternalInvariantViolation),
        }
    }

    /// Mutably borrows the read contract captured before queue insertion.
    /// # Errors
    ///
    /// Returns an invariant error when this context is not a read request.
    pub(super) fn read_mut(&mut self) -> DriverResult<&mut PreparedRead> {
        match &mut self.prepared {
            PreparedRequest::Read(request) => Ok(request),
            _ => Err(DriverError::InternalInvariantViolation),
        }
    }

    /// Borrows the write contract captured before queue insertion.
    /// # Errors
    ///
    /// Returns an invariant error when this context is not a write request.
    pub(super) fn write(&self) -> DriverResult<&PreparedWrite> {
        match &self.prepared {
            PreparedRequest::Write(request) => Ok(request),
            _ => Err(DriverError::InternalInvariantViolation),
        }
    }

    /// Borrows the complete QueryDirectory payload sealed before queue insertion.
    /// # Errors
    ///
    /// Returns an invariant error when this context is not a query-directory request.
    pub(super) fn query_directory(&self) -> DriverResult<&PreparedQueryDirectory> {
        match &self.prepared {
            PreparedRequest::DirectoryControl(PreparedDirectoryControl::QueryDirectory(
                request,
            )) => Ok(request),
            _ => Err(DriverError::InternalInvariantViolation),
        }
    }

    /// Borrows the complete QueryEa payload sealed before queue insertion.
    /// # Errors
    ///
    /// Returns an invariant error when this context is not a query-EA request.
    pub(super) fn query_ea(&self) -> DriverResult<&PreparedQueryEa> {
        match &self.prepared {
            PreparedRequest::QueryEa(request) => Ok(request),
            _ => Err(DriverError::InternalInvariantViolation),
        }
    }

    /// Borrows the opaque query-security output target.
    /// # Errors
    ///
    /// Returns an invariant error when this context is not a file-scoped query-security request.
    pub(super) fn query_security_parts(
        &mut self,
    ) -> DriverResult<(SecuritySelection, &mut CapturedQuerySecurityOutput)> {
        match &mut self.prepared {
            PreparedRequest::QuerySecurity { selection, output } => Ok((*selection, output)),
            _ => Err(DriverError::InternalInvariantViolation),
        }
    }

    /// Borrows the immutable set-security snapshot owned by this queued request.
    /// # Errors
    ///
    /// Returns an invariant error when this context is not a file-scoped set-security request.
    pub(super) fn set_security_parts(&self) -> DriverResult<(SecuritySelection, &[u8])> {
        match &self.prepared {
            PreparedRequest::SetSecurity {
                selection,
                descriptor,
            } => Ok((*selection, descriptor.as_slice())),
            _ => Err(DriverError::InternalInvariantViolation),
        }
    }
}

/// Complete set of requests accepted by the asynchronous device lane.
#[derive(Debug)]
pub(crate) enum PreparedRequest {
    /// Create/open request.
    Create,
    /// Read request with its complete output contract captured.
    Read(PreparedRead),
    /// Write request with scalar parameters and input mapping captured.
    Write(PreparedWrite),
    /// File information query.
    QueryInformation,
    /// File information mutation.
    SetInformation,
    /// Volume information query.
    QueryVolumeInformation,
    /// Volume information mutation.
    SetVolumeInformation,
    /// Directory request with all requestor-owned auxiliary input captured.
    DirectoryControl(PreparedDirectoryControl),
    /// File-system control with a sealed minor-function classification.
    FileSystemControl(FileSystemControlMinorFunction),
    /// Flush request.
    FlushBuffers,
    /// Extended-attribute query with an owned selection list.
    QueryEa(PreparedQueryEa),
    /// Extended-attribute mutation.
    SetEa,
    /// Query-security request with locked output pages and a system mapping.
    QuerySecurity {
        /// Security components selected in requestor context.
        selection: SecuritySelection,
        /// Opaque native target that never exposes requestor memory to Rust.
        output: CapturedQuerySecurityOutput,
    },
    /// Set-security request with an owned, bounded descriptor snapshot.
    SetSecurity {
        /// Security components selected in requestor context.
        selection: SecuritySelection,
        /// Owned descriptor snapshot.
        descriptor: CapturedSetSecurityDescriptor,
    },
    /// Filesystem shutdown request.
    Shutdown,
}

impl PreparedRequest {
    /// Captures one queued request and its stable cancellation identity.
    /// # Errors
    ///
    /// Returns a completion payload when the major is not queueable or security capture fails.
    fn capture(
        target: &ActiveIrp<'_>,
        stack: super::CurrentIrpStackLocation<'_>,
        major: DispatchMajor,
    ) -> Result<(Self, QueueCancellationKey), IrpCompletion> {
        let generic_key = || QueueCancellationKey::from_stack(stack);
        match major {
            DispatchMajor::Create => Ok((Self::Create, generic_key())),
            DispatchMajor::Read => Ok((
                Self::Read(PreparedRead::capture(target, stack)?),
                generic_key(),
            )),
            DispatchMajor::Write => Ok((
                Self::Write(PreparedWrite::capture(target, stack)?),
                generic_key(),
            )),
            DispatchMajor::QueryInformation => Ok((Self::QueryInformation, generic_key())),
            DispatchMajor::SetInformation => Ok((Self::SetInformation, generic_key())),
            DispatchMajor::QueryVolumeInformation => {
                Ok((Self::QueryVolumeInformation, generic_key()))
            }
            DispatchMajor::SetVolumeInformation => Ok((Self::SetVolumeInformation, generic_key())),
            DispatchMajor::DirectoryControl => Ok((
                match stack.directory_control_minor() {
                    DirectoryControlMinorFunction::QueryDirectory => {
                        let query = stack.query_directory().map_err(IrpCompletion::from_error)?;
                        let pattern = capture_directory_pattern(target, stack)?;
                        Self::DirectoryControl(PreparedDirectoryControl::QueryDirectory(
                            PreparedQueryDirectory {
                                stack: query,
                                pattern,
                            },
                        ))
                    }
                    DirectoryControlMinorFunction::NotifyChangeDirectory => {
                        stack
                            .notify_directory()
                            .map_err(IrpCompletion::from_error)?;
                        Self::DirectoryControl(PreparedDirectoryControl::NotifyChangeDirectory)
                    }
                    DirectoryControlMinorFunction::Unsupported => {
                        return Err(IrpCompletion::from_error(DriverError::InvalidDeviceRequest));
                    }
                },
                generic_key(),
            )),
            DispatchMajor::FileSystemControl => {
                let minor = stack.file_system_control_minor();
                let key = match minor {
                    FileSystemControlMinorFunction::MountVolume => QueueCancellationKey::Device,
                    FileSystemControlMinorFunction::UserFsRequest => generic_key(),
                    FileSystemControlMinorFunction::Unsupported => {
                        return Err(IrpCompletion::from_error(DriverError::InvalidDeviceRequest));
                    }
                };
                Ok((Self::FileSystemControl(minor), key))
            }
            DispatchMajor::FlushBuffers => Ok((Self::FlushBuffers, generic_key())),
            DispatchMajor::QueryEa => {
                let query = stack.query_ea().map_err(IrpCompletion::from_error)?;
                let selection = capture_ea_selection(target, stack)?;
                Ok((
                    Self::QueryEa(PreparedQueryEa {
                        stack: query,
                        selection,
                    }),
                    generic_key(),
                ))
            }
            DispatchMajor::SetEa => Ok((Self::SetEa, generic_key())),
            DispatchMajor::QuerySecurity => {
                let query = stack.query_security().map_err(IrpCompletion::from_error)?;
                let output = CapturedQuerySecurityOutput::capture(
                    target,
                    query.length(),
                    query.selection(),
                )?;
                Ok((
                    Self::QuerySecurity {
                        selection: query.selection(),
                        output,
                    },
                    QueueCancellationKey::File(
                        stack
                            .file_object()
                            .map_err(IrpCompletion::from_error)?
                            .address()
                            .into(),
                    ),
                ))
            }
            DispatchMajor::SetSecurity => {
                let set = stack.set_security().map_err(IrpCompletion::from_error)?;
                let descriptor = CapturedSetSecurityDescriptor::capture(
                    target,
                    set.security_descriptor_source(),
                    set.selection(),
                )?;
                Ok((
                    Self::SetSecurity {
                        selection: set.selection(),
                        descriptor,
                    },
                    QueueCancellationKey::File(
                        stack
                            .file_object()
                            .map_err(IrpCompletion::from_error)?
                            .address()
                            .into(),
                    ),
                ))
            }
            DispatchMajor::Shutdown => Ok((Self::Shutdown, QueueCancellationKey::Device)),
            DispatchMajor::Close
            | DispatchMajor::Cleanup
            | DispatchMajor::DeviceControl
            | DispatchMajor::LockControl => {
                Err(IrpCompletion::from_error(DriverError::InvalidDeviceRequest))
            }
        }
    }
}

/// Captures and validates a QueryDirectory filename pattern.
/// # Errors
///
/// Returns a completion when the descriptor cannot be captured or its payload is malformed.
fn capture_directory_pattern(
    target: &ActiveIrp<'_>,
    stack: super::CurrentIrpStackLocation<'_>,
) -> Result<PreparedDirectoryPattern, IrpCompletion> {
    let Some(source) = stack
        .query_directory_file_name()
        .map_err(IrpCompletion::from_error)?
    else {
        return Ok(PreparedDirectoryPattern::All);
    };
    let Some(captured) = CapturedRequestorInput::capture_directory_pattern(target, source)? else {
        return Ok(PreparedDirectoryPattern::All);
    };
    decode_directory_pattern(captured.as_slice())
}

/// Converts a captured little-endian UTF-16 payload into its driver-owned representation.
/// # Errors
///
/// Returns an invalid-parameter completion for a truncated UTF-16 code unit or an allocation
/// completion when the owned vector cannot be constructed.
fn decode_directory_pattern(bytes: &[u8]) -> Result<PreparedDirectoryPattern, IrpCompletion> {
    let (pairs, remainder) = bytes.as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(IrpCompletion::from_error(DriverError::InvalidParameter));
    }
    let mut units = DriverVec::try_with_capacity(pairs.len()).map_err(IrpCompletion::from_error)?;
    for pair in pairs {
        let unit = u16::from_le_bytes(*pair);
        units.try_push(unit).map_err(IrpCompletion::from_error)?;
    }
    Ok(PreparedDirectoryPattern::Name(units))
}

/// Captures the requestor-owned QueryEa name list or seals its scalar selection.
/// # Errors
///
/// Returns a completion when the name list cannot be captured or an owned copy cannot be
/// allocated.
fn capture_ea_selection(
    target: &ActiveIrp<'_>,
    stack: super::CurrentIrpStackLocation<'_>,
) -> Result<PreparedEaSelection, IrpCompletion> {
    if let Some((source, length)) = stack
        .query_ea_name_list()
        .map_err(IrpCompletion::from_error)?
    {
        let captured = CapturedRequestorInput::capture_ea_name_list(target, source, length)?;
        let mut bytes = DriverVec::try_with_capacity(captured.as_slice().len())
            .map_err(IrpCompletion::from_error)?;
        bytes
            .try_extend_from_copy_slice(captured.as_slice())
            .map_err(IrpCompletion::from_error)?;
        return Ok(PreparedEaSelection::Names(bytes));
    }

    let selection = stack
        .query_ea()
        .map_err(IrpCompletion::from_error)?
        .selection();
    Ok(match selection {
        super::EaSelection::All => PreparedEaSelection::All,
        super::EaSelection::Index(index) => PreparedEaSelection::Index(index),
    })
}

/// Stable FILE_OBJECT identity used by cleanup while the IRP is queue-owned.
#[derive(Clone, Copy, Debug)]
enum QueueCancellationKey {
    /// Request is scoped to one FILE_OBJECT.
    File(QueueFileObjectAddress),
    /// Request is device-wide and never selected by FILE_OBJECT cleanup.
    Device,
}

impl QueueCancellationKey {
    /// Captures the stack FILE_OBJECT when present without retaining the stack itself.
    fn from_stack(stack: super::CurrentIrpStackLocation<'_>) -> Self {
        stack.file_object().map_or(Self::Device, |file_object| {
            Self::File(file_object.address().into())
        })
    }

    /// Compares this captured identity with an `IoCsqRemoveNextIrp` context.
    fn matches(self, context: PVOID) -> bool {
        match self {
            Self::File(file_object) => file_object.matches(context),
            Self::Device => false,
        }
    }
}

/// Exposed-provenance address of the FILE_OBJECT kept live by a pending IRP.
#[derive(Clone, Copy, Debug)]
struct QueueFileObjectAddress(NonZeroUsize);

impl From<KernelFileObject> for QueueFileObjectAddress {
    fn from(file_object: KernelFileObject) -> Self {
        let Some(address) = NonZeroUsize::new(file_object.as_ptr().expose_provenance()) else {
            crate::kernel::fatal::KernelWideInconsistency::async_executor_state_corruption()
                .bugcheck();
        };
        Self(address)
    }
}

impl QueueFileObjectAddress {
    /// Returns whether a CSQ cleanup context names this captured FILE_OBJECT.
    fn matches(self, context: PVOID) -> bool {
        NonZeroUsize::new(context.expose_provenance()) == Some(self.0)
    }
}

/// Opaque C-owned output target for one query-security neither-I/O request.
#[derive(Debug)]
pub(crate) struct CapturedQuerySecurityOutput {
    /// Native ownership state; Rust never dereferences the opaque pending target.
    #[cfg(not(test))]
    state: QuerySecurityOutputState,
    /// Exact descriptor length fixed before the request enters the actor mailbox.
    length: NonZeroUsize,
}

/// Native query-output lifecycle after requestor-context capture.
#[cfg(not(test))]
#[derive(Debug)]
enum QuerySecurityOutputState {
    /// Exact output pages are locked and waiting for one owned copy.
    Pending(NonNull<c_void>),
    /// The native copy consumed and unlocked the target.
    Written,
}

// SAFETY: The native target owns locked pages and exposes no dereferenceable Rust pointer. Its
// unique state crosses threads only inside the typed device-mailbox payload and is consumed by the
// device actor or released by Drop.
unsafe impl Send for CapturedQuerySecurityOutput {}

impl CapturedQuerySecurityOutput {
    /// Captures exactly the descriptor-sized output prefix in requestor process context.
    /// # Errors
    ///
    /// Returns overflow with the exact required length, a native capture failure, or an invariant
    /// error when the native ownership contract is violated.
    fn capture(
        target: &ActiveIrp<'_>,
        declared_length: super::IrpBufferLength,
        selection: SecuritySelection,
    ) -> Result<Self, IrpCompletion> {
        let required = selection.query_descriptor_length();
        if declared_length.as_usize() < required {
            let completion = match IrpCompletion::buffer_overflow(required) {
                Ok(completion) => completion,
                Err(error) => IrpCompletion::from_error(error),
            };
            return Err(completion);
        }
        let Some(length) = NonZeroUsize::new(required) else {
            return Err(IrpCompletion::from_error(
                DriverError::InternalInvariantViolation,
            ));
        };

        #[cfg(not(test))]
        {
            let declared_native = wdk_sys::ULONG::try_from(declared_length.as_usize())
                .map_err(|_| IrpCompletion::from_error(DriverError::InvalidParameter))?;
            let required_native = wdk_sys::ULONG::try_from(required)
                .map_err(|_| IrpCompletion::from_error(DriverError::InvalidParameter))?;
            let irp = unsafe {
                // SAFETY: Dispatch retains the received IRP until capture returns.
                target.irp.as_ref()
            };
            let mut native = core::ptr::null_mut();
            let mut reported_required = 0;
            let status = unsafe {
                // SAFETY: The native boundary locks exactly `required_native` bytes in requestor
                // context and returns only an opaque owning target.
                ffi::ext4win_capture_query_security_output(
                    core::ptr::addr_of_mut!(native),
                    core::ptr::addr_of_mut!(reported_required),
                    irp.UserBuffer,
                    declared_native,
                    required_native,
                    irp.RequestorMode,
                )
            };
            ensure_native_success(status)?;
            let Some(native) = NonNull::new(native) else {
                return Err(IrpCompletion::from_error(
                    DriverError::InternalInvariantViolation,
                ));
            };
            if reported_required != required_native {
                unsafe {
                    // SAFETY: Native capture transferred this opaque target to the failed Rust
                    // constructor, which must release it exactly once.
                    ffi::ext4win_release_query_security_output(native.as_ptr());
                }
                return Err(IrpCompletion::from_error(
                    DriverError::InternalInvariantViolation,
                ));
            }
            Ok(Self {
                state: QuerySecurityOutputState::Pending(native),
                length,
            })
        }
        #[cfg(test)]
        {
            let _: &ActiveIrp<'_> = target;
            let _: NonZeroUsize = length;
            Err(IrpCompletion::from_error(DriverError::InvalidDeviceRequest))
        }
    }

    /// Copies an owned Rust descriptor through C into the locked requestor pages.
    /// # Errors
    ///
    /// Returns an invariant error when the descriptor length differs from the plan sealed at queue
    /// entry or the opaque native target rejects the owned source.
    pub(crate) fn copy_from_owned(&mut self, source: &[u8]) -> DriverResult<()> {
        if source.len() != self.length.get() {
            return Err(DriverError::InternalInvariantViolation);
        }
        #[cfg(not(test))]
        {
            let source_length = wdk_sys::ULONG::try_from(source.len())
                .map_err(|_| DriverError::InternalInvariantViolation)?;
            let state = core::mem::replace(&mut self.state, QuerySecurityOutputState::Written);
            let QuerySecurityOutputState::Pending(native) = state else {
                return Err(DriverError::InternalInvariantViolation);
            };
            let status = unsafe {
                // SAFETY: `source` is owned kernel memory and `native` is the unique opaque target.
                // The call consumes the target and unlocks its pages before returning.
                ffi::ext4win_copy_query_security_output(
                    native.as_ptr(),
                    source.as_ptr().cast(),
                    source_length,
                )
            };
            if status < STATUS_SUCCESS {
                return Err(DriverError::InternalInvariantViolation);
            }
            Ok(())
        }
        #[cfg(test)]
        {
            let _: &[u8] = source;
            Err(DriverError::InvalidDeviceRequest)
        }
    }
}

impl Drop for CapturedQuerySecurityOutput {
    fn drop(&mut self) {
        #[cfg(not(test))]
        if let QuerySecurityOutputState::Pending(native) = &self.state {
            unsafe {
                // SAFETY: Drop owns the only unconsumed native target and releases it exactly once.
                ffi::ext4win_release_query_security_output(native.as_ptr());
            }
        }
    }
}

/// Naturally aligned, C-owned set-security snapshot validated after its bounded copy.
#[derive(Debug)]
pub(crate) struct CapturedSetSecurityDescriptor {
    /// First byte of the native nonpaged allocation.
    address: NonNull<u8>,
    /// Exact logical descriptor length validated by the native boundary.
    length: NonZeroUsize,
}

// SAFETY: Capture returns an immutable nonpaged allocation without requestor aliases. Unique
// ownership crosses threads only inside the typed device-mailbox payload and Drop frees it once.
unsafe impl Send for CapturedSetSecurityDescriptor {}

impl CapturedSetSecurityDescriptor {
    /// Captures, validates, and owns one requestor descriptor in a single native operation.
    /// # Errors
    ///
    /// Returns a native boundary failure or an invariant error when successful output ownership is
    /// incomplete.
    fn capture(
        target: &ActiveIrp<'_>,
        source: NonNull<c_void>,
        selection: SecuritySelection,
    ) -> Result<Self, IrpCompletion> {
        #[cfg(not(test))]
        {
            let irp = unsafe {
                // SAFETY: Dispatch retains the received IRP until capture returns.
                target.irp.as_ref()
            };
            let mut snapshot = core::ptr::null_mut();
            let mut captured_length = 0;
            let status = unsafe {
                // SAFETY: The native boundary performs only bounded requestor reads, copies into a
                // naturally aligned owned allocation, then validates that immutable snapshot.
                ffi::ext4win_capture_set_security_descriptor(
                    source.as_ptr().cast(),
                    irp.RequestorMode,
                    selection.required_information(),
                    SET_SECURITY_DESCRIPTOR_MAXIMUM,
                    core::ptr::addr_of_mut!(snapshot),
                    core::ptr::addr_of_mut!(captured_length),
                )
            };
            ensure_native_success(status)?;
            let Some(address) = NonNull::new(snapshot.cast::<u8>()) else {
                return Err(IrpCompletion::from_error(
                    DriverError::InternalInvariantViolation,
                ));
            };
            let length = usize::try_from(captured_length)
                .ok()
                .and_then(NonZeroUsize::new);
            let Some(length) = length else {
                unsafe {
                    // SAFETY: Capture transferred the non-null allocation to this failed
                    // constructor, which must release it exactly once.
                    ffi::ext4win_release_set_security_descriptor(address.as_ptr().cast());
                }
                return Err(IrpCompletion::from_error(
                    DriverError::InternalInvariantViolation,
                ));
            };
            Ok(Self { address, length })
        }
        #[cfg(test)]
        {
            let _: &ActiveIrp<'_> = target;
            let _: NonNull<c_void> = source;
            let _: SecuritySelection = selection;
            Err(IrpCompletion::from_error(DriverError::InvalidDeviceRequest))
        }
    }

    /// Borrows the immutable descriptor snapshot.
    fn as_slice(&self) -> &[u8] {
        unsafe {
            // SAFETY: Native capture allocated and initialized exactly `length` bytes, and the
            // borrow cannot outlive the owning value.
            core::slice::from_raw_parts(self.address.as_ptr(), self.length.get())
        }
    }
}

impl Drop for CapturedSetSecurityDescriptor {
    fn drop(&mut self) {
        #[cfg(not(test))]
        unsafe {
            // SAFETY: This value uniquely owns the native snapshot allocation.
            ffi::ext4win_release_set_security_descriptor(self.address.as_ptr().cast());
        }
    }
}

/// Preserves an NTSTATUS raised by the native requestor-memory boundary.
/// # Errors
///
/// Returns a completion preserving `status` when it is a failed NTSTATUS.
#[cfg(not(test))]
fn ensure_native_success(status: NTSTATUS) -> Result<(), IrpCompletion> {
    if status >= STATUS_SUCCESS {
        Ok(())
    } else {
        Err(IrpCompletion::from_native_failure(status))
    }
}

#[cfg(test)]
mod tests {
    use core::ffi::c_void;

    use super::{
        PreparedDirectoryPattern, PreparedRequest, QueueCancellationKey, QueueContext,
        QueueContextOwnership, decode_directory_pattern,
    };
    use crate::irp::{
        DispatchMajor, FileSystemControlMinorFunction, IrpCompletion, KernelIrp,
        PreparedDirectoryControl, ReceivedIrp,
    };

    /// Builds a typed target and installs its current stack pointer.
    fn build_target(
        device: &mut wdk_sys::DEVICE_OBJECT,
        irp: &mut wdk_sys::IRP,
        stack: &mut wdk_sys::IO_STACK_LOCATION,
    ) -> Option<ReceivedIrp> {
        irp.Tail
            .Overlay
            .__bindgen_anon_2
            .__bindgen_anon_1
            .CurrentStackLocation = core::ptr::from_mut(stack);
        ReceivedIrp::decode(core::ptr::from_mut(device), core::ptr::from_mut(irp)).ok()
    }

    /// Captures one prepared request through its lifetime-bound active IRP view.
    /// # Errors
    ///
    /// Returns the exact immediate completion when requestor input capture fails.
    fn capture_context(
        received: &mut ReceivedIrp,
        major: DispatchMajor,
    ) -> Result<QueueContextOwnership, IrpCompletion> {
        received.with_active(|active| QueueContext::capture(active, major))
    }

    /// # Panics
    ///
    /// Panics when cleanup or close inherits requestor-state allocation instead of its typed
    /// lifecycle identity.
    #[test]
    fn lifecycle_requests_capture_allocation_free_identities() {
        let mut device = wdk_sys::DEVICE_OBJECT::default();
        let mut file_object = wdk_sys::FILE_OBJECT::default();

        for (major, expected) in [
            (DispatchMajor::Cleanup, QueueContextOwnership::Cleanup),
            (DispatchMajor::Close, QueueContextOwnership::Close),
        ] {
            let mut irp = wdk_sys::IRP::default();
            let mut stack = wdk_sys::IO_STACK_LOCATION {
                FileObject: core::ptr::addr_of_mut!(file_object),
                ..wdk_sys::IO_STACK_LOCATION::default()
            };
            let target = build_target(&mut device, &mut irp, &mut stack);
            assert!(target.is_some());
            if let Some(mut target) = target {
                let context = capture_context(&mut target, major);
                assert!(context.is_ok());
                assert!(matches!(
                    (context, expected),
                    (
                        Ok(QueueContextOwnership::Cleanup),
                        QueueContextOwnership::Cleanup
                    ) | (
                        Ok(QueueContextOwnership::Close),
                        QueueContextOwnership::Close
                    )
                ));
            }
        }
    }

    /// # Panics
    ///
    /// Panics when queue classification can change after requestor-context capture.
    #[test]
    fn prepared_major_and_minor_classification_is_sealed() {
        let mut device = wdk_sys::DEVICE_OBJECT::default();
        let mut file_object = wdk_sys::FILE_OBJECT::default();

        let mut irp = wdk_sys::IRP::default();
        let mut stack = wdk_sys::IO_STACK_LOCATION {
            MajorFunction: u8::try_from(wdk_sys::IRP_MJ_READ).unwrap_or_default(),
            FileObject: core::ptr::addr_of_mut!(file_object),
            ..wdk_sys::IO_STACK_LOCATION::default()
        };
        let target = build_target(&mut device, &mut irp, &mut stack);
        assert!(target.is_some());
        if let Some(mut target) = target {
            let context = capture_context(&mut target, DispatchMajor::Read);
            assert!(context.is_ok());
            if let Ok(context) = context {
                stack.MajorFunction = u8::try_from(wdk_sys::IRP_MJ_WRITE).unwrap_or_default();
                assert_eq!(u32::from(stack.MajorFunction), wdk_sys::IRP_MJ_WRITE);
                assert!(matches!(
                    context,
                    QueueContextOwnership::Captured(context)
                        if matches!(context.prepared(), PreparedRequest::Read(_))
                ));
            }
        }

        let mut irp = wdk_sys::IRP::default();
        let mut stack = wdk_sys::IO_STACK_LOCATION {
            MajorFunction: u8::try_from(wdk_sys::IRP_MJ_DIRECTORY_CONTROL).unwrap_or_default(),
            MinorFunction: u8::try_from(wdk_sys::IRP_MN_QUERY_DIRECTORY).unwrap_or_default(),
            FileObject: core::ptr::addr_of_mut!(file_object),
            ..wdk_sys::IO_STACK_LOCATION::default()
        };
        stack.Parameters.QueryDirectory = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_6 {
            Length: 128,
            FileName: core::ptr::null_mut(),
            FileInformationClass: wdk_sys::_FILE_INFORMATION_CLASS::FileDirectoryInformation,
            __bindgen_padding_0: 0,
            FileIndex: 0,
        };
        let target = build_target(&mut device, &mut irp, &mut stack);
        assert!(target.is_some());
        if let Some(mut target) = target {
            let context = capture_context(&mut target, DispatchMajor::DirectoryControl);
            assert!(context.is_ok());
            if let Ok(context) = context {
                stack.MinorFunction = u8::MAX;
                assert_eq!(stack.MinorFunction, u8::MAX);
                assert!(matches!(
                    context,
                    QueueContextOwnership::Captured(context)
                        if matches!(
                            context.prepared(),
                            PreparedRequest::DirectoryControl(
                                PreparedDirectoryControl::QueryDirectory(_)
                            )
                        )
                ));
            }
        }

        let mut irp = wdk_sys::IRP::default();
        let mut stack = wdk_sys::IO_STACK_LOCATION {
            MajorFunction: u8::try_from(wdk_sys::IRP_MJ_FILE_SYSTEM_CONTROL).unwrap_or_default(),
            MinorFunction: 1,
            ..wdk_sys::IO_STACK_LOCATION::default()
        };
        let target = build_target(&mut device, &mut irp, &mut stack);
        assert!(target.is_some());
        if let Some(mut target) = target {
            let context = capture_context(&mut target, DispatchMajor::FileSystemControl);
            assert!(context.is_ok());
            if let Ok(context) = context {
                stack.MinorFunction = u8::MAX;
                assert_eq!(stack.MinorFunction, u8::MAX);
                assert!(matches!(
                    context,
                    QueueContextOwnership::Captured(context)
                        if matches!(
                            context.prepared(),
                            PreparedRequest::FileSystemControl(
                                FileSystemControlMinorFunction::MountVolume
                            )
                        )
                ));
            }
        }
    }

    /// # Panics
    ///
    /// Panics when queued read capture retains the mutable caller mapping or re-reads stack state.
    #[test]
    fn prepared_read_seals_stack_and_borrows_the_original_output_mapping() {
        let mut device = wdk_sys::DEVICE_OBJECT::default();
        let mut file_object = wdk_sys::FILE_OBJECT::default();
        let mut output = [0xAA_u8; 32];
        let mut irp = wdk_sys::IRP::default();
        irp.AssociatedIrp.SystemBuffer = output.as_mut_ptr().cast::<c_void>();
        let mut stack = wdk_sys::IO_STACK_LOCATION {
            MajorFunction: u8::try_from(wdk_sys::IRP_MJ_READ).unwrap_or_default(),
            FileObject: core::ptr::addr_of_mut!(file_object),
            ..wdk_sys::IO_STACK_LOCATION::default()
        };
        stack.Parameters.Read = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_4 {
            Length: u32::try_from(output.len()).unwrap_or_default(),
            __bindgen_padding_0: 0,
            Key: 41,
            Flags: 0,
            ByteOffset: wdk_sys::LARGE_INTEGER { QuadPart: 8192 },
        };
        let target = build_target(&mut device, &mut irp, &mut stack);
        assert!(target.is_some());
        if let Some(mut target) = target {
            let context = capture_context(&mut target, DispatchMajor::Read);
            assert!(context.is_ok());
            if let Ok(mut context) = context {
                stack.Parameters.Read = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_4 {
                    Length: 1,
                    __bindgen_padding_0: 0,
                    Key: 0,
                    Flags: 0,
                    ByteOffset: wdk_sys::LARGE_INTEGER { QuadPart: 0 },
                };
                let rewritten_length = unsafe {
                    // SAFETY: The test assigned the `Read` union arm immediately above.
                    stack.Parameters.Read.Length
                };
                assert_eq!(rewritten_length, 1);
                let prepared = context.read_mut();
                assert!(prepared.is_ok());
                if let Ok(prepared) = prepared {
                    assert_eq!(prepared.stack().length().as_usize(), output.len());
                    assert_eq!(
                        prepared.stack().key(),
                        crate::irp::ByteRangeLockKey::from_ulong(41)
                    );
                    prepared.output_mut().fill(0x55);
                }
            }
        }
        assert_eq!(output, [0x55; 32]);
    }

    /// # Panics
    ///
    /// Panics when queued write capture copies caller data or re-reads mutable stack state.
    #[test]
    fn prepared_write_seals_stack_and_borrows_the_original_input_mapping() {
        let mut device = wdk_sys::DEVICE_OBJECT::default();
        let mut file_object = wdk_sys::FILE_OBJECT::default();
        let mut input = [0xAA_u8; 32];
        let mut irp = wdk_sys::IRP::default();
        irp.AssociatedIrp.SystemBuffer = input.as_mut_ptr().cast::<c_void>();
        let mut stack = wdk_sys::IO_STACK_LOCATION {
            MajorFunction: u8::try_from(wdk_sys::IRP_MJ_WRITE).unwrap_or_default(),
            FileObject: core::ptr::addr_of_mut!(file_object),
            ..wdk_sys::IO_STACK_LOCATION::default()
        };
        stack.Parameters.Write = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_5 {
            Length: u32::try_from(input.len()).unwrap_or_default(),
            __bindgen_padding_0: 0,
            Key: 73,
            Flags: 0,
            ByteOffset: wdk_sys::LARGE_INTEGER { QuadPart: 16_384 },
        };
        let target = build_target(&mut device, &mut irp, &mut stack);
        assert!(target.is_some());
        if let Some(mut target) = target {
            let context = capture_context(&mut target, DispatchMajor::Write);
            assert!(context.is_ok());
            if let Ok(context) = context {
                stack.Parameters.Write = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_5 {
                    Length: 1,
                    __bindgen_padding_0: 0,
                    Key: 0,
                    Flags: 0,
                    ByteOffset: wdk_sys::LARGE_INTEGER { QuadPart: 0 },
                };
                input[0] = 0x55;
                let rewritten_length = unsafe {
                    // SAFETY: The test assigned the `Write` union arm immediately above.
                    stack.Parameters.Write.Length
                };
                assert_eq!(rewritten_length, 1);
                let prepared = context.write();
                assert!(prepared.is_ok());
                if let Ok(prepared) = prepared {
                    assert_eq!(prepared.stack().length().as_usize(), input.len());
                    assert_eq!(
                        prepared.stack().starting_point(),
                        crate::irp::WriteStartingPoint::Absolute(
                            ext4_core::FileOffset::from_bytes(16_384)
                        )
                    );
                    assert_eq!(
                        prepared.stack().key(),
                        crate::irp::ByteRangeLockKey::from_ulong(73)
                    );
                    let mut snapshot = [0_u8; 32];
                    assert_eq!(prepared.copy_window(0, &mut snapshot), Ok(()));
                    assert_eq!(snapshot.first().copied(), Some(0x55));
                    assert_eq!(snapshot.len(), input.len());
                    let mut middle = [0_u8; 5];
                    assert_eq!(prepared.copy_window(7, &mut middle), Ok(()));
                    assert_eq!(middle.as_slice(), &input[7..12]);
                    assert_eq!(prepared.copy_window(input.len(), &mut []), Ok(()));
                    let mut outside = [0_u8; 1];
                    assert_eq!(
                        prepared.copy_window(input.len(), &mut outside),
                        Err(crate::kernel::status::DriverError::InternalInvariantViolation)
                    );
                }
            }
        }
    }

    /// # Panics
    ///
    /// Panics when direct-I/O capture ignores the MDL byte count or loses its mapped address.
    #[test]
    fn prepared_write_requires_an_exactly_covering_mdl_mapping() {
        let mut device = wdk_sys::DEVICE_OBJECT::default();
        let mut file_object = wdk_sys::FILE_OBJECT::default();
        let mut input = [0x3C_u8; 16];

        for (byte_count, expected_status) in [
            (
                u32::try_from(input.len().saturating_sub(1)).unwrap_or_default(),
                Some(wdk_sys::STATUS_INVALID_PARAMETER),
            ),
            (u32::try_from(input.len()).unwrap_or_default(), None),
        ] {
            let mut mdl = wdk_sys::MDL {
                MappedSystemVa: input.as_mut_ptr().cast::<c_void>(),
                ByteCount: byte_count,
                MdlFlags: i16::try_from(wdk_sys::MDL_MAPPED_TO_SYSTEM_VA).unwrap_or_default(),
                ..wdk_sys::MDL::default()
            };
            let mut irp = wdk_sys::IRP {
                MdlAddress: core::ptr::addr_of_mut!(mdl),
                ..wdk_sys::IRP::default()
            };
            let mut stack = wdk_sys::IO_STACK_LOCATION {
                MajorFunction: u8::try_from(wdk_sys::IRP_MJ_WRITE).unwrap_or_default(),
                FileObject: core::ptr::addr_of_mut!(file_object),
                ..wdk_sys::IO_STACK_LOCATION::default()
            };
            stack.Parameters.Write = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_5 {
                Length: u32::try_from(input.len()).unwrap_or_default(),
                __bindgen_padding_0: 0,
                Key: 0,
                Flags: 0,
                ByteOffset: wdk_sys::LARGE_INTEGER { QuadPart: 0 },
            };
            let target = build_target(&mut device, &mut irp, &mut stack);
            assert!(target.is_some());
            if let Some(mut target) = target {
                let context = capture_context(&mut target, DispatchMajor::Write);
                match expected_status {
                    Some(expected_status) => {
                        assert!(context.is_err());
                        if let Err(completion) = context {
                            assert_eq!(completion.status(), expected_status);
                        }
                    }
                    None => {
                        assert!(context.is_ok());
                        if let Ok(context) = context {
                            let prepared = context.write();
                            assert!(prepared.is_ok());
                            if let Ok(prepared) = prepared {
                                let mut snapshot = [0_u8; 4];
                                assert_eq!(prepared.copy_window(6, &mut snapshot), Ok(()));
                                assert_eq!(snapshot, [0x3C; 4]);
                            }
                        }
                    }
                }
            }
        }
    }

    /// # Panics
    ///
    /// Panics when zero-byte write capture requires a mapping or a non-empty write accepts none.
    #[test]
    fn prepared_write_mapping_is_required_exactly_for_nonempty_input() {
        let mut device = wdk_sys::DEVICE_OBJECT::default();
        let mut file_object = wdk_sys::FILE_OBJECT::default();

        for (length, expected_status) in [(0, None), (1, Some(wdk_sys::STATUS_INVALID_PARAMETER))] {
            let mut irp = wdk_sys::IRP::default();
            let mut stack = wdk_sys::IO_STACK_LOCATION {
                MajorFunction: u8::try_from(wdk_sys::IRP_MJ_WRITE).unwrap_or_default(),
                FileObject: core::ptr::addr_of_mut!(file_object),
                ..wdk_sys::IO_STACK_LOCATION::default()
            };
            stack.Parameters.Write = wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_5 {
                Length: length,
                __bindgen_padding_0: 0,
                Key: 0,
                Flags: 0,
                ByteOffset: wdk_sys::LARGE_INTEGER { QuadPart: 0 },
            };
            let target = build_target(&mut device, &mut irp, &mut stack);
            assert!(target.is_some());
            if let Some(mut target) = target {
                let context = capture_context(&mut target, DispatchMajor::Write);
                match expected_status {
                    None => {
                        assert!(context.is_ok());
                        if let Ok(context) = context {
                            let prepared = context.write();
                            assert!(prepared.is_ok());
                            if let Ok(prepared) = prepared {
                                assert_eq!(prepared.copy_window(0, &mut []), Ok(()));
                            }
                        }
                    }
                    Some(expected_status) => {
                        assert!(context.is_err());
                        if let Err(completion) = context {
                            assert_eq!(completion.status(), expected_status);
                        }
                    }
                }
            }
        }
    }

    /// # Panics
    ///
    /// Panics when captured UTF-16 bytes are not converted without retaining the source buffer.
    #[test]
    fn captured_directory_pattern_becomes_owned_utf16() {
        let pattern = decode_directory_pattern(&[b'a', 0, 0x42, 0x30]);
        assert!(pattern.is_ok());
        assert!(matches!(pattern, Ok(PreparedDirectoryPattern::Name(_))));
        if let Ok(PreparedDirectoryPattern::Name(units)) = pattern {
            assert_eq!(units.as_slice(), &[u16::from(b'a'), 0x3042]);
        }
    }

    /// # Panics
    ///
    /// Panics when a truncated UTF-16 code unit is accepted.
    #[test]
    fn captured_directory_pattern_rejects_truncated_code_unit() {
        let pattern = decode_directory_pattern(b"a");
        assert!(pattern.is_err());
        if let Err(completion) = pattern {
            assert_eq!(completion.status(), wdk_sys::STATUS_INVALID_PARAMETER);
        }
    }

    /// # Panics
    ///
    /// Panics when cleanup matching re-decodes a stack or selects a device-wide request.
    #[test]
    fn cancellation_key_filters_file_and_device_requests() {
        let mut device = wdk_sys::DEVICE_OBJECT::default();
        let mut file_object = wdk_sys::FILE_OBJECT::default();
        let mut other_file = wdk_sys::FILE_OBJECT::default();
        let mut irp = wdk_sys::IRP::default();
        let mut stack = wdk_sys::IO_STACK_LOCATION {
            MajorFunction: u8::try_from(wdk_sys::IRP_MJ_CREATE).unwrap_or_default(),
            FileObject: core::ptr::addr_of_mut!(file_object),
            ..wdk_sys::IO_STACK_LOCATION::default()
        };
        let target = build_target(&mut device, &mut irp, &mut stack);
        assert!(target.is_some());
        if let Some(mut target) = target {
            let context = capture_context(&mut target, DispatchMajor::Create);
            assert!(context.is_ok());
            if let Ok(QueueContextOwnership::Captured(context)) = context {
                assert!(context.matches_cancellation_context(
                    core::ptr::addr_of_mut!(file_object).cast::<c_void>()
                ));
                assert!(!context.matches_cancellation_context(
                    core::ptr::addr_of_mut!(other_file).cast::<c_void>()
                ));
            }
        }

        let mut irp = wdk_sys::IRP::default();
        let mut stack = wdk_sys::IO_STACK_LOCATION {
            MajorFunction: u8::try_from(wdk_sys::IRP_MJ_SHUTDOWN).unwrap_or_default(),
            ..wdk_sys::IO_STACK_LOCATION::default()
        };
        let target = build_target(&mut device, &mut irp, &mut stack);
        assert!(target.is_some());
        if let Some(mut target) = target {
            let context = capture_context(&mut target, DispatchMajor::Shutdown);
            assert!(context.is_ok());
            if let Ok(QueueContextOwnership::Captured(context)) = context {
                assert!(!context.matches_cancellation_context(
                    core::ptr::addr_of_mut!(file_object).cast::<c_void>()
                ));
            }
        }
    }

    /// # Panics
    ///
    /// Panics when cleanup cancels a queued flush that remains legal after the cleanup barrier, or
    /// when it stops cancelling an ordinary request from the same handle.
    #[test]
    fn cleanup_preserves_queued_flushes() {
        let flush = QueueContext {
            prepared: PreparedRequest::FlushBuffers,
            cancellation_key: QueueCancellationKey::Device,
        };
        assert!(!flush.cleanup_cancel_eligible());

        let ordinary = QueueContext {
            prepared: PreparedRequest::QueryInformation,
            cancellation_key: QueueCancellationKey::Device,
        };
        assert!(ordinary.cleanup_cancel_eligible());
    }

    /// # Panics
    ///
    /// Panics when DriverContext[0] publication is not taken and cleared exactly once.
    #[test]
    fn queue_context_publish_peek_take_clears_slot_zero() {
        let mut device = wdk_sys::DEVICE_OBJECT::default();
        let mut irp = wdk_sys::IRP::default();
        let mut stack = wdk_sys::IO_STACK_LOCATION {
            MajorFunction: u8::try_from(wdk_sys::IRP_MJ_CREATE).unwrap_or_default(),
            ..wdk_sys::IO_STACK_LOCATION::default()
        };
        let mut target = build_target(&mut device, &mut irp, &mut stack);
        let kernel_irp = KernelIrp::from_raw(core::ptr::addr_of_mut!(irp));
        assert!(kernel_irp.is_some());
        let context = target
            .as_mut()
            .map(|target| capture_context(target, DispatchMajor::Create));
        let context = context.transpose();
        assert!(context.is_ok());
        if let (Some(kernel_irp), Ok(Some(context))) = (kernel_irp, context) {
            kernel_irp.publish_queue_context(context);
            let queued = kernel_irp.take_queue_context();
            assert!(matches!(
                queued,
                QueueContextOwnership::Captured(ref context)
                    if matches!(context.prepared(), PreparedRequest::Create)
            ));
            drop(queued);

            let overlay = unsafe {
                // SAFETY: The test reads the tail overlay after the unique queue-context take.
                irp.Tail.Overlay
            };
            let driver_storage = unsafe {
                // SAFETY: Queue publication selected this nested driver-context union arm.
                overlay.__bindgen_anon_1.__bindgen_anon_1
            };
            assert!(driver_storage.DriverContext[0].is_null());
        }
    }

    /// # Panics
    ///
    /// Panics when allocation-free lifecycle markers alias or fail to round-trip exactly.
    #[test]
    fn lifecycle_queue_context_markers_remain_distinct() {
        let mut irp = wdk_sys::IRP::default();
        let Some(kernel_irp) = KernelIrp::from_raw(core::ptr::addr_of_mut!(irp)) else {
            return;
        };

        kernel_irp.publish_queue_context(QueueContextOwnership::Cleanup);
        let cleanup = kernel_irp.take_queue_context();
        assert!(matches!(cleanup, QueueContextOwnership::Cleanup));

        kernel_irp.publish_queue_context(QueueContextOwnership::Close);
        let close = kernel_irp.take_queue_context();
        assert!(matches!(close, QueueContextOwnership::Close));

        let overlay = unsafe {
            // SAFETY: The test reads the tail overlay after both unique queue-context takes.
            irp.Tail.Overlay
        };
        let driver_storage = unsafe {
            // SAFETY: Queue publication selected this nested driver-context union arm.
            overlay.__bindgen_anon_1.__bindgen_anon_1
        };
        assert!(driver_storage.DriverContext[0].is_null());
    }

    /// # Panics
    ///
    /// Panics when query-security overflow or native capture failure loses its status payload.
    #[test]
    fn security_completion_statuses_preserve_required_information() {
        let overflow = IrpCompletion::buffer_overflow(321);
        assert!(overflow.is_ok());
        if let Ok(overflow) = overflow {
            assert_eq!(overflow.status(), wdk_sys::STATUS_BUFFER_OVERFLOW);
            assert_eq!(overflow.information().as_ulong_ptr(), 321);
        }

        let native = IrpCompletion::from_native_failure(wdk_sys::STATUS_ACCESS_VIOLATION);
        assert_eq!(native.status(), wdk_sys::STATUS_ACCESS_VIOLATION);
        assert_eq!(native.information().as_ulong_ptr(), 0);
    }
}
