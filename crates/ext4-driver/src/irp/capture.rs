//! Requestor-context capture for requests that cross the PASSIVE_LEVEL device queue.

use alloc::boxed::Box;
use core::{ffi::c_void, num::NonZeroUsize, ptr::NonNull};

use wdk_sys::PVOID;
#[cfg(not(test))]
use wdk_sys::{NTSTATUS, STATUS_SUCCESS};

#[cfg(not(test))]
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

/// Maximum writable prefix pinned by one retrieval request; excess results use NextVcn continuation.
const RETRIEVAL_OUTPUT_MAXIMUM: usize = 128 * 1024;

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
    /// Enumerate from the scalar cursor position captured in `QueryEaStack`.
    Enumerate,
    /// Requestor-owned FILE_GET_EA_INFORMATION bytes.
    Names(DriverVec<u8>),
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
    /// Operation-local cache policy sealed before leaving requestor context.
    cache_policy: super::DataCachePolicy,
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
        let cache_policy = target.data_cache_policy();
        let stack = stack.read().map_err(IrpCompletion::from_error)?;
        let output = CapturedReadOutput::capture(target, stack.length())?;
        Ok(Self {
            kind,
            cache_policy,
            stack,
            output,
        })
    }

    /// Returns the request origin sealed at capture.
    pub(crate) const fn kind(&self) -> DataIoKind {
        self.kind
    }

    /// Returns the request's sealed intermediate-buffering policy.
    pub(crate) const fn cache_policy(&self) -> super::DataCachePolicy {
        self.cache_policy
    }

    /// Returns the immutable scalar read parameters.
    pub(crate) const fn stack(&self) -> ReadStack {
        self.stack
    }

    /// Returns the first output byte for transfer-alignment validation.
    pub(crate) const fn output_address(&self) -> Option<NonNull<u8>> {
        self.output.address()
    }

    /// Copies driver-owned bytes into one checked output window.
    /// # Errors
    ///
    /// Returns an invariant error when the selected range exceeds the captured read output or the
    /// native copy boundary rejects it.
    pub(crate) fn copy_window(&mut self, offset: usize, source: &[u8]) -> DriverResult<()> {
        self.output.copy_window(offset, source)
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

#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
// SAFETY: The I/O Manager keeps the system buffer or locked MDL mapping valid until the owning IRP
// completes. The mapping remains opaque and is consumed only through checked native copies.
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

    /// Copies driver-owned bytes into one checked range without admitting requestor memory into
    /// Rust's aliasing model.
    /// # Errors
    ///
    /// Returns an error when the selected range exceeds the prepared output.
    #[expect(
        unsafe_code,
        reason = "the pending IRP retains the opaque mapped output through this checked copy"
    )]
    fn copy_window(&mut self, offset: usize, source: &[u8]) -> DriverResult<()> {
        match self {
            Self::Empty => unsafe {
                // SAFETY: The empty representation permits only a zero-length checked copy.
                super::copy_requestor_output_window(None, 0, offset, source)
            },
            Self::Mapped(mapping) => unsafe {
                // SAFETY: The pending IRP keeps the system mapping writable, and safe callers
                // cannot construct `source` as an alias of this opaque requestor range.
                super::copy_requestor_output_window(
                    Some(mapping.address()),
                    mapping.len(),
                    offset,
                    source,
                )
            },
        }
    }
}

/// Write parameters and system mapping captured before queue insertion.
#[derive(Debug)]
pub(crate) struct PreparedWrite {
    /// Handle or paging origin sealed before the IRP can leave requestor context.
    kind: DataIoKind,
    /// Operation-local cache policy sealed before leaving requestor context.
    cache_policy: super::DataCachePolicy,
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
        let cache_policy = target.data_cache_policy();
        let stack = stack.write().map_err(IrpCompletion::from_error)?;
        let input = CapturedWriteInput::capture(target, stack.length())?;
        Ok(Self {
            kind,
            cache_policy,
            stack,
            input,
        })
    }

    /// Returns the request origin sealed at capture.
    pub(crate) const fn kind(&self) -> DataIoKind {
        self.kind
    }

    /// Returns the request's sealed intermediate-buffering policy.
    pub(crate) const fn cache_policy(&self) -> super::DataCachePolicy {
        self.cache_policy
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
    /// input.
    #[expect(
        unsafe_code,
        reason = "the pending IRP retains the opaque mapped input through this checked copy"
    )]
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
                unsafe {
                    // SAFETY: The pending IRP keeps the system mapping readable, and safe callers
                    // cannot construct `destination` as an alias of this opaque requestor range.
                    super::copy_requestor_input_window(
                        Some(mapping.address()),
                        mapping.len(),
                        offset,
                        destination,
                    )
                }
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

#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
// SAFETY: The immutable nonpaged allocation is uniquely owned and crosses threads only inside the
// typed device-mailbox payload whose publication requires `Send`.
unsafe impl Send for CapturedRequestorInput {}

impl CapturedRequestorInput {
    /// Captures a bounded EA name list before an IRP is queued.
    /// # Errors
    ///
    /// Returns a completion preserving native capture failure or allocation validation failure.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
        )
    )]
    fn capture_ea_name_list(
        target: &ActiveIrp<'_>,
        source: NonNull<c_void>,
        length: super::IrpBufferLength,
    ) -> Result<Self, IrpCompletion> {
        #[cfg(not(test))]
        {
            let length = wdk_sys::ULONG::try_from(length.as_usize())
                .map_err(|_| IrpCompletion::from_error(DriverError::InvalidParameter))?;
            let requestor_mode = target.requestor_mode();
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
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
        )
    )]
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
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn as_slice(&self) -> &[u8] {
        unsafe {
            // SAFETY: Native capture initialized exactly `length` bytes in this owned allocation.
            core::slice::from_raw_parts(self.address.as_ptr(), self.length.get())
        }
    }
}

impl Drop for CapturedRequestorInput {
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
        )
    )]
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
    /// Derives the independent progress lane from the immutable captured request.
    pub(super) fn execution_class(&self) -> super::scheduler::ExecutionClass {
        match self {
            Self::Cleanup | Self::Close => super::scheduler::ExecutionClass::Finalization,
            Self::Captured(context) => context.execution_class(),
        }
    }

    /// Moves the sealed command to its sole control operation.
    /// # Errors
    /// Rejects another request kind or a command already consumed.
    pub(super) fn take_identity(&mut self) -> DriverResult<crate::identity::IdentityCommand> {
        let Self::Captured(context) = self else {
            return Err(DriverError::InternalInvariantViolation);
        };
        match &mut context.prepared {
            PreparedRequest::IdentityControl(command) => {
                let owned = core::mem::replace(command, crate::identity::IdentityCommand::Consumed);
                owned.uuid()?;
                Ok(owned)
            }
            _ => Err(DriverError::InternalInvariantViolation),
        }
    }
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
    ) -> DriverResult<(SecuritySelection, &mut CapturedRequestorOutput)> {
        match self {
            Self::Captured(context) => context.query_security_parts(),
            Self::Cleanup | Self::Close => Err(DriverError::InternalInvariantViolation),
        }
    }

    /// Borrows the sealed retrieval payload through the completion owner's unique lease.
    /// # Errors
    /// Returns an invariant error for a different prepared request.
    pub(super) fn retrieval_parts(&mut self) -> DriverResult<(u64, &mut CapturedRequestorOutput)> {
        match self {
            Self::Captured(context) => context.retrieval_parts(),
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
    /// Paging must progress even while ordinary Cache Manager work owns its execution slots.
    pub(super) fn execution_class(&self) -> super::scheduler::ExecutionClass {
        let paging = match &self.prepared {
            PreparedRequest::Read(read) => read.kind() == DataIoKind::Paging,
            PreparedRequest::Write(write) => write.kind() == DataIoKind::Paging,
            _ => false,
        };
        if paging {
            super::scheduler::ExecutionClass::Paging
        } else {
            super::scheduler::ExecutionClass::Ordinary
        }
    }

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
    ) -> DriverResult<(SecuritySelection, &mut CapturedRequestorOutput)> {
        match &mut self.prepared {
            PreparedRequest::QuerySecurity { selection, output } => Ok((*selection, output)),
            _ => Err(DriverError::InternalInvariantViolation),
        }
    }

    /// Borrows the copied starting VCN and native output owner.
    /// # Errors
    /// Returns an invariant error for a different prepared request.
    pub(super) fn retrieval_parts(&mut self) -> DriverResult<(u64, &mut CapturedRequestorOutput)> {
        match &mut self.prepared {
            PreparedRequest::RetrievalPointers {
                starting_vcn,
                output,
            } => Ok((*starting_vcn, output)),
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
    /// Owned validated administrator identity command.
    IdentityControl(crate::identity::IdentityCommand),
    /// Cache Manager page acquisition; release notifications bypass this cancellable lane.
    Mdl(super::MdlTransfer),
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
    /// Retrieval request with a copied VCN and uniquely owned locked output pages.
    RetrievalPointers {
        /// Nonnegative file-space allocation-unit index decoded in requestor context.
        starting_vcn: u64,
        /// Bounded native output capacity retained until publication or cancellation.
        output: CapturedRequestorOutput,
    },
    /// Byte-range lock or unlock request whose live lock parameters remain IRP-owned.
    LockControl,
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
        output: CapturedRequestorOutput,
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
    /// Device-scoped reversible removal preparation; no FILE_OBJECT is required.
    QueryRemove,
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
            DispatchMajor::DeviceControl => {
                let control = stack.device_control().map_err(IrpCompletion::from_error)?;
                let length = control.input_buffer_length().as_usize();
                if length > ext4_security::MAX_MAPPING_BYTES {
                    return Err(IrpCompletion::from_error(DriverError::InvalidBufferSize));
                }
                let input = target
                    .buffered_input(control.input_buffer_length())
                    .map_err(IrpCompletion::from_error)?;
                let command = match control.io_control_code() {
                    ext4_security::QUERY_IDENTITY_IOCTL => crate::identity::IdentityCommand::Query(
                        ext4_core::FilesystemUuid::from_bytes(input.try_into().map_err(|_| {
                            IrpCompletion::from_error(DriverError::InvalidParameter)
                        })?),
                    ),
                    ext4_security::REPLACE_IDENTITY_IOCTL => {
                        crate::identity::IdentityCommand::Replace(
                            ext4_security::Replacement::decode(input)
                                .map_err(|error| IrpCompletion::from_error(error.into()))?,
                        )
                    }
                    _ => return Err(IrpCompletion::from_error(DriverError::InvalidDeviceRequest)),
                };
                Ok((Self::IdentityControl(command), QueueCancellationKey::Device))
            }
            DispatchMajor::Create => Ok((Self::Create, generic_key())),
            DispatchMajor::Read => Ok((
                match stack.mdl_action(false).map_err(IrpCompletion::from_error)? {
                    Some(super::MdlAction::Read) => Self::Mdl(super::MdlTransfer::Read),
                    Some(
                        super::MdlAction::ReadComplete
                        | super::MdlAction::WriteComplete
                        | super::MdlAction::Write,
                    ) => return Err(IrpCompletion::from_error(DriverError::InvalidParameter)),
                    None => Self::Read(PreparedRead::capture(target, stack)?),
                },
                generic_key(),
            )),
            DispatchMajor::Write => Ok((
                match stack.mdl_action(true).map_err(IrpCompletion::from_error)? {
                    Some(super::MdlAction::Write) => Self::Mdl(super::MdlTransfer::Write),
                    Some(
                        super::MdlAction::ReadComplete
                        | super::MdlAction::WriteComplete
                        | super::MdlAction::Read,
                    ) => return Err(IrpCompletion::from_error(DriverError::InvalidParameter)),
                    None => Self::Write(PreparedWrite::capture(target, stack)?),
                },
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
                    DirectoryControlMinorFunction::NotifyChangeDirectoryEx => {
                        let information_class = stack
                            .notify_directory_ex()
                            .map_err(IrpCompletion::from_error)?;
                        // The FsRtl registration path implements only the standard minor-function
                        // contract. Do not submit EX requests with an incompatible output layout.
                        return Err(IrpCompletion::from_error(match information_class {
                            super::DirectoryNotifyInformationClass::Standard
                            | super::DirectoryNotifyInformationClass::Extended
                            | super::DirectoryNotifyInformationClass::Full => {
                                DriverError::NotSupported
                            }
                        }));
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
                    FileSystemControlMinorFunction::UserFsRequest => {
                        let control = stack
                            .file_system_control()
                            .map_err(IrpCompletion::from_error)?;
                        if control.fs_control_code() == super::FsControlCode::GetRetrievalPointers {
                            return capture_retrieval_pointers(target, control, generic_key());
                        }
                        generic_key()
                    }
                    FileSystemControlMinorFunction::Unsupported => {
                        return Err(IrpCompletion::from_error(DriverError::InvalidDeviceRequest));
                    }
                };
                Ok((Self::FileSystemControl(minor), key))
            }
            DispatchMajor::LockControl => Ok((Self::LockControl, generic_key())),
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
                let capacity = query
                    .length()
                    .as_usize()
                    .min(ext4_security::MAX_DESCRIPTOR_BYTES);
                let output = CapturedRequestorOutput::capture(target, capacity)?;
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
            DispatchMajor::PlugAndPlay if stack.pnp_minor() == super::PnpMinor::QueryRemove => {
                Ok((Self::QueryRemove, QueueCancellationKey::Device))
            }
            DispatchMajor::Close | DispatchMajor::Cleanup | DispatchMajor::PlugAndPlay => {
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

    Ok(PreparedEaSelection::Enumerate)
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

/// Seals the signed input and a bounded output prefix before leaving requestor context.
/// The limit bounds pinned pages per IRP; larger declared buffers use continuation semantics.
/// # Errors
/// Returns malformed input, short output, or native capture failure before queue publication.
#[cfg_attr(
    not(test),
    expect(
        unsafe_code,
        reason = "the native boundary copies Type3 input under SEH before the request can leave its process"
    )
)]
fn capture_retrieval_pointers(
    target: &ActiveIrp<'_>,
    stack: super::FileSystemControlStack,
    key: QueueCancellationKey,
) -> Result<(PreparedRequest, QueueCancellationKey), IrpCompletion> {
    if stack.input_buffer_length().as_usize() < 8 {
        return Err(IrpCompletion::from_error(DriverError::InvalidParameter));
    }
    if stack.output_buffer_length().as_usize() < 32 {
        return Err(IrpCompletion::from_error(DriverError::BufferTooSmall));
    }
    #[cfg(not(test))]
    let starting_vcn = {
        let mut value = 0_i64;
        let status = unsafe {
            // SAFETY: Dispatch owns this live FSCTL IRP in requestor context. Native capture
            // probes and copies only the fixed STARTING_VCN prefix, never forming a Rust view.
            ffi::ext4win_capture_starting_vcn(target.irp.as_ptr(), core::ptr::addr_of_mut!(value))
        };
        ensure_native_success(status)?;
        u64::try_from(value)
            .map_err(|_| IrpCompletion::from_error(DriverError::InvalidParameter))?
    };
    #[cfg(test)]
    let starting_vcn = 0;
    let capacity = stack
        .output_buffer_length()
        .as_usize()
        .min(RETRIEVAL_OUTPUT_MAXIMUM);
    let output = CapturedRequestorOutput::capture(target, capacity)?;
    Ok((
        PreparedRequest::RetrievalPointers {
            starting_vcn,
            output,
        },
        key,
    ))
}

/// Locked requestor pages retained across actor suspension without a Rust memory view.
/// Capture fixes capacity; one owned prefix publication consumes the pages, and Drop releases
/// an unpublished target. The pending IRP owns this value until completion or cancellation.
#[derive(Debug)]
pub(crate) struct CapturedRequestorOutput {
    /// Exact writable prefix fixed in requestor context.
    capacity: usize,
    /// Unique native ownership; no pointer is exposed to consumers.
    #[cfg(not(test))]
    state: RequestorOutputState,
}

/// Publication consumes native ownership even when the native copy rejects an invalid source.
#[cfg(not(test))]
#[derive(Debug)]
enum RequestorOutputState {
    /// Size probe owns no native pages.
    Empty,
    /// Native owner of locked pages and their system mapping.
    Pending(NonNull<c_void>),
    /// Publication has released the native owner.
    Consumed,
}

#[expect(
    unsafe_code,
    reason = "the opaque native owner retains locked pages until consuming publication or Drop"
)]
// SAFETY: The unique output never forms a Rust reference to requestor memory. Its native MDL
// owns page residency independently of the requestor thread, and every terminal path releases it.
unsafe impl Send for CapturedRequestorOutput {}

impl CapturedRequestorOutput {
    /// Locks only the supplied writable prefix before queue insertion.
    /// # Errors
    /// Returns a native page-lock failure or invalid-parameter for empty/excess capacity.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "dispatch owns the IRP and its requestor process while C probes and locks output pages"
        )
    )]
    fn capture(target: &ActiveIrp<'_>, capacity: usize) -> Result<Self, IrpCompletion> {
        if capacity == 0 {
            return Ok(Self {
                capacity,
                #[cfg(not(test))]
                state: RequestorOutputState::Empty,
            });
        }
        #[cfg(not(test))]
        {
            let length = wdk_sys::ULONG::try_from(capacity)
                .map_err(|_| IrpCompletion::from_error(DriverError::InvalidParameter))?;
            let user_buffer = unsafe {
                // SAFETY: Dispatch retains the live IRP through queue-time capture.
                (*target.irp.as_ptr()).UserBuffer
            };
            let mut native = core::ptr::null_mut();
            let status = unsafe {
                // SAFETY: Capacity was bounded by the request decoder. C probes and locks exactly
                // that writable prefix in requestor context and transfers an opaque owner.
                ffi::ext4win_capture_requestor_output(
                    core::ptr::addr_of_mut!(native),
                    user_buffer,
                    length,
                    target.requestor_mode(),
                )
            };
            ensure_native_success(status)?;
            let native = NonNull::new(native).ok_or_else(|| {
                IrpCompletion::from_error(DriverError::InternalInvariantViolation)
            })?;
            Ok(Self {
                capacity,
                state: RequestorOutputState::Pending(native),
            })
        }
        #[cfg(test)]
        {
            let _retained = (target, capacity);
            Err(IrpCompletion::from_error(DriverError::InvalidDeviceRequest))
        }
    }

    /// Capacity of the locked prefix, independent of the requestor's larger declared buffer.
    pub(crate) const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Publishes initialized owned bytes and releases native page ownership before returning.
    /// # Errors
    /// Returns an invariant failure for excess source length or repeated publication.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "C consumes the unique opaque target while copying disjoint initialized driver bytes"
        )
    )]
    pub(crate) fn copy_from_owned(&mut self, source: &[u8]) -> DriverResult<()> {
        if source.len() > self.capacity {
            return Err(DriverError::InternalInvariantViolation);
        }
        #[cfg(not(test))]
        {
            let length = wdk_sys::ULONG::try_from(source.len())
                .map_err(|_| DriverError::InternalInvariantViolation)?;
            let RequestorOutputState::Pending(native) =
                core::mem::replace(&mut self.state, RequestorOutputState::Consumed)
            else {
                return Err(DriverError::InternalInvariantViolation);
            };
            let status = unsafe {
                // SAFETY: Source is owned initialized memory disjoint from the opaque requestor
                // mapping; the unique native target is consumed, including on failure.
                ffi::ext4win_copy_requestor_output(native.as_ptr(), source.as_ptr().cast(), length)
            };
            if status < STATUS_SUCCESS {
                return Err(DriverError::InternalInvariantViolation);
            }
            Ok(())
        }
        #[cfg(test)]
        {
            Err(DriverError::InvalidDeviceRequest)
        }
    }
}

impl Drop for CapturedRequestorOutput {
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "Drop owns and releases the sole unpublished native page target"
        )
    )]
    fn drop(&mut self) {
        #[cfg(not(test))]
        if let RequestorOutputState::Pending(native) = &self.state {
            unsafe {
                // SAFETY: This target has never been consumed; Drop releases it exactly once.
                ffi::ext4win_release_requestor_output(native.as_ptr());
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

#[expect(
    unsafe_code,
    reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
)]
// SAFETY: Capture returns an immutable nonpaged allocation without requestor aliases. Unique
// ownership crosses threads only inside the typed device-mailbox payload and Drop frees it once.
unsafe impl Send for CapturedSetSecurityDescriptor {}

impl CapturedSetSecurityDescriptor {
    /// Captures, validates, and owns one requestor descriptor in a single native operation.
    /// # Errors
    ///
    /// Returns a native boundary failure or an invariant error when successful output ownership is
    /// incomplete.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
        )
    )]
    fn capture(
        target: &ActiveIrp<'_>,
        source: NonNull<c_void>,
        selection: SecuritySelection,
    ) -> Result<Self, IrpCompletion> {
        #[cfg(not(test))]
        {
            let mut snapshot = core::ptr::null_mut();
            let mut captured_length = 0;
            let status = unsafe {
                // SAFETY: The native boundary performs only bounded requestor reads, copies into a
                // naturally aligned owned allocation, then validates that immutable snapshot.
                ffi::ext4win_capture_set_security_descriptor(
                    source.as_ptr().cast(),
                    target.requestor_mode(),
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
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn as_slice(&self) -> &[u8] {
        unsafe {
            // SAFETY: Native capture allocated and initialized exactly `length` bytes, and the
            // borrow cannot outlive the owning value.
            core::slice::from_raw_parts(self.address.as_ptr(), self.length.get())
        }
    }
}

impl Drop for CapturedSetSecurityDescriptor {
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
        )
    )]
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
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
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
        unsafe {
            // SAFETY: Both mutable fixture objects remain live for the returned test owner.
            ReceivedIrp::decode(core::ptr::from_mut(device), core::ptr::from_mut(irp)).ok()
        }
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
    /// Panics if page acquisition tries to map absent caller byte buffers.
    #[test]
    fn mdl_requests_are_captured_before_ordinary_byte_buffer_mapping() {
        let mut device = wdk_sys::DEVICE_OBJECT::default();
        let mut file_object = wdk_sys::FILE_OBJECT::default();
        for (major, minor, expected) in [
            (DispatchMajor::Read, 2, crate::irp::MdlTransfer::Read),
            (DispatchMajor::Write, 2, crate::irp::MdlTransfer::Write),
        ] {
            let mut irp = wdk_sys::IRP::default();
            let mut stack = wdk_sys::IO_STACK_LOCATION {
                MinorFunction: minor,
                FileObject: core::ptr::from_mut(&mut file_object),
                ..wdk_sys::IO_STACK_LOCATION::default()
            };
            stack.Parameters.Read.Length = 8192;
            let target = build_target(&mut device, &mut irp, &mut stack);
            assert!(target.is_some());
            let Some(mut target) = target else {
                return;
            };
            let captured = capture_context(&mut target, major);
            assert!(captured.is_ok());
            if let Ok(QueueContextOwnership::Captured(context)) = captured {
                assert!(
                    matches!(context.prepared, PreparedRequest::Mdl(action) if action == expected)
                );
            }
        }
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
    /// Panics when lock-control loses its sealed major classification or handle cancellation key.
    #[test]
    fn lock_control_capture_is_file_scoped() {
        let mut device = wdk_sys::DEVICE_OBJECT::default();
        let mut file_object = wdk_sys::FILE_OBJECT::default();
        let mut other_file = wdk_sys::FILE_OBJECT::default();
        let mut irp = wdk_sys::IRP::default();
        let mut stack = wdk_sys::IO_STACK_LOCATION {
            MajorFunction: u8::try_from(wdk_sys::IRP_MJ_LOCK_CONTROL).unwrap_or_default(),
            FileObject: core::ptr::addr_of_mut!(file_object),
            ..wdk_sys::IO_STACK_LOCATION::default()
        };
        let target = build_target(&mut device, &mut irp, &mut stack);
        assert!(target.is_some());
        if let Some(mut target) = target {
            let context = capture_context(&mut target, DispatchMajor::LockControl);
            assert!(context.is_ok());
            if let Ok(QueueContextOwnership::Captured(context)) = context {
                assert!(matches!(context.prepared(), PreparedRequest::LockControl));
                assert!(context.matches_cancellation_context(
                    core::ptr::addr_of_mut!(file_object).cast::<c_void>()
                ));
                assert!(!context.matches_cancellation_context(
                    core::ptr::addr_of_mut!(other_file).cast::<c_void>()
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

    /// # Errors
    /// Returns fixture capture or allocation failure.
    /// # Panics
    /// Panics if a native cache transfer escapes its captured direction, capacity or FILE_OBJECT.
    #[test]
    #[expect(
        unsafe_code,
        reason = "exclusive stack fixtures retain every device, FILE_OBJECT, IRP and mapped byte through completion"
    )]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "fixture errors propagate while assertions verify native transfer admission"
    )]
    fn cache_transfers_borrow_the_captured_prefix_and_file_object()
    -> Result<(), crate::kernel::status::DriverError> {
        use crate::irp::{OwnedIrp, PendingIrp};
        use crate::kernel::status::DriverError;
        for major in [DispatchMajor::Read, DispatchMajor::Write] {
            for capacity in [0_u32, 8] {
                let mut device = wdk_sys::DEVICE_OBJECT::default();
                let mut file = wdk_sys::FILE_OBJECT::default();
                let mut bytes = [0_u8; 8];
                let address = core::ptr::NonNull::new(bytes.as_mut_ptr());
                let mut irp = wdk_sys::IRP::default();
                irp.AssociatedIrp.SystemBuffer = bytes.as_mut_ptr().cast();
                let mut stack = wdk_sys::IO_STACK_LOCATION {
                    FileObject: core::ptr::from_mut(&mut file),
                    MajorFunction: u8::try_from(major.table_index())
                        .map_err(|_| DriverError::InvalidParameter)?,
                    ..Default::default()
                };
                match major {
                    DispatchMajor::Read => {
                        stack.Parameters.Read =
                            wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_4 {
                                Length: capacity,
                                ..Default::default()
                            }
                    }
                    DispatchMajor::Write => {
                        stack.Parameters.Write =
                            wdk_sys::_IO_STACK_LOCATION__bindgen_ty_1__bindgen_ty_5 {
                                Length: capacity,
                                ..Default::default()
                            }
                    }
                    _ => return Err(DriverError::InternalInvariantViolation),
                }
                let mut received = build_target(&mut device, &mut irp, &mut stack)
                    .ok_or(DriverError::InvalidParameter)?;
                let device = received.device();
                let context = capture_context(&mut received, major)
                    .map_err(|completion| DriverError::CacheManagerFailure(completion.status()))?;
                let raw = PendingIrp::from_received(received, context).publish();
                let mut owned = unsafe {
                    // SAFETY: The fixture exclusively removes the just-published IRP and retains
                    // all of its backing objects until the returned owner is completed below.
                    OwnedIrp::from_queued_raw(device, raw)
                };
                let capacity =
                    usize::try_from(capacity).map_err(|_| DriverError::InvalidParameter)?;
                if major == DispatchMajor::Read {
                    assert_eq!(
                        owned.request().cache_write_transfer(0).err(),
                        Some(DriverError::InternalInvariantViolation)
                    );
                    assert_eq!(
                        owned
                            .request()
                            .cache_read_transfer(capacity.saturating_add(1))
                            .err(),
                        Some(DriverError::BufferTooSmall)
                    );
                    let transfer = owned.request().cache_read_transfer(capacity)?;
                    assert_eq!(transfer.length(), capacity);
                    assert_eq!(
                        transfer.file_object().as_ptr(),
                        core::ptr::from_mut(&mut file)
                    );
                    assert_eq!(
                        transfer.address(),
                        if capacity == 0 { None } else { address }
                    );
                } else {
                    assert_eq!(
                        owned.request().cache_read_transfer(0).err(),
                        Some(DriverError::InternalInvariantViolation)
                    );
                    assert_eq!(
                        owned
                            .request()
                            .cache_write_transfer(capacity.saturating_add(1))
                            .err(),
                        Some(DriverError::BufferTooSmall)
                    );
                    let transfer = owned.request().cache_write_transfer(capacity)?;
                    assert_eq!(transfer.length(), capacity);
                    assert_eq!(
                        transfer.file_object().as_ptr(),
                        core::ptr::from_mut(&mut file)
                    );
                    assert_eq!(
                        transfer.address(),
                        if capacity == 0 { None } else { address }
                    );
                }
                stack.FileObject = core::ptr::null_mut();
                assert!(stack.FileObject.is_null());
                let error = if major == DispatchMajor::Read {
                    owned.request().cache_read_transfer(0).err()
                } else {
                    owned.request().cache_write_transfer(0).err()
                };
                assert_eq!(error, Some(DriverError::InvalidParameter));
                let completion = owned.prepare_result(Ok(IrpCompletion::EMPTY));
                assert_eq!(completion.notify(), wdk_sys::STATUS_SUCCESS);
            }
        }
        Ok(())
    }

    /// # Panics
    ///
    /// Panics when queued read capture retains the mutable caller mapping or re-reads stack state.
    #[test]
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn prepared_read_seals_stack_and_borrows_the_original_output_mapping() {
        let mut device = wdk_sys::DEVICE_OBJECT::default();
        let mut file_object = wdk_sys::FILE_OBJECT::default();
        let mut output = [0xAA_u8; 32];
        let mut irp = wdk_sys::IRP {
            Flags: wdk_sys::IRP_NOCACHE,
            ..wdk_sys::IRP::default()
        };
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
                irp.Flags = 0;
                assert_eq!(irp.Flags, 0);
                let prepared = context.read_mut();
                assert!(prepared.is_ok());
                if let Ok(prepared) = prepared {
                    assert_eq!(
                        prepared.cache_policy(),
                        crate::irp::DataCachePolicy::NonCached
                    );
                    assert_eq!(prepared.stack().length().as_usize(), output.len());
                    assert_eq!(
                        prepared.stack().key(),
                        crate::irp::ByteRangeLockKey::from_ulong(41)
                    );
                    assert_eq!(prepared.copy_window(0, &[0x55; 32]), Ok(()));
                }
            }
        }
        assert_eq!(output, [0x55; 32]);
    }

    /// # Panics
    ///
    /// Panics when queued write capture copies caller data or re-reads mutable stack state.
    #[test]
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn prepared_write_seals_stack_and_borrows_the_original_input_mapping() {
        let mut device = wdk_sys::DEVICE_OBJECT::default();
        let mut file_object = wdk_sys::FILE_OBJECT::default();
        let mut input = [0xAA_u8; 32];
        let mut irp = wdk_sys::IRP {
            Flags: wdk_sys::IRP_NOCACHE,
            ..wdk_sys::IRP::default()
        };
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
                irp.Flags = 0;
                assert_eq!(irp.Flags, 0);
                let prepared = context.write();
                assert!(prepared.is_ok());
                if let Ok(prepared) = prepared {
                    assert_eq!(
                        prepared.cache_policy(),
                        crate::irp::DataCachePolicy::NonCached
                    );
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

        for (major, minor) in [
            (DispatchMajor::Shutdown, 0),
            (DispatchMajor::PlugAndPlay, 1),
        ] {
            let mut irp = wdk_sys::IRP::default();
            let mut stack = wdk_sys::IO_STACK_LOCATION {
                MajorFunction: u8::try_from(major.table_index()).unwrap_or_default(),
                MinorFunction: minor,
                ..wdk_sys::IO_STACK_LOCATION::default()
            };
            let target = build_target(&mut device, &mut irp, &mut stack);
            assert!(target.is_some());
            if let Some(mut target) = target {
                let context = capture_context(&mut target, major);
                assert!(context.is_ok());
                if let Ok(QueueContextOwnership::Captured(context)) = context {
                    assert!(!context.matches_cancellation_context(
                        core::ptr::addr_of_mut!(file_object).cast::<c_void>()
                    ));
                    if major == DispatchMajor::PlugAndPlay {
                        assert!(matches!(context.prepared(), PreparedRequest::QueryRemove));
                    }
                }
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
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn queue_context_publish_peek_take_clears_slot_zero() {
        let mut device = wdk_sys::DEVICE_OBJECT::default();
        let mut irp = wdk_sys::IRP::default();
        let mut stack = wdk_sys::IO_STACK_LOCATION {
            MajorFunction: u8::try_from(wdk_sys::IRP_MJ_CREATE).unwrap_or_default(),
            ..wdk_sys::IO_STACK_LOCATION::default()
        };
        let mut target = build_target(&mut device, &mut irp, &mut stack);
        let kernel_irp = unsafe {
            // SAFETY: The stack-local fixture remains live throughout this test.
            KernelIrp::from_raw(core::ptr::addr_of_mut!(irp))
        };
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
    #[expect(
        unsafe_code,
        reason = "this audited kernel or raw-memory item documents each unsafe operation with a local SAFETY invariant"
    )]
    fn lifecycle_queue_context_markers_remain_distinct() {
        let mut irp = wdk_sys::IRP::default();
        let Some(kernel_irp) = (unsafe {
            // SAFETY: The stack-local fixture remains live throughout this test.
            KernelIrp::from_raw(core::ptr::addr_of_mut!(irp))
        }) else {
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
