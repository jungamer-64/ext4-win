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
    security_descriptor::SecuritySelection,
    state::KernelFileObject,
};

use super::{
    DirectoryControlMinorFunction, DispatchMajor, DispatchTarget, FileSystemControlMinorFunction,
    IrpCompletion,
};

/// Maximum self-relative security descriptor accepted from one untrusted requestor.
#[cfg(not(test))]
const SET_SECURITY_DESCRIPTOR_MAXIMUM: wdk_sys::ULONG = 65_536;

/// Request identity captured before the IRP enters the cancel-safe queue.
#[derive(Debug)]
pub(super) struct QueueContext {
    /// Complete typed request classification plus any requestor-context capture.
    prepared: PreparedRequest,
    /// Stable cleanup cancellation identity; no queued stack re-decode is required.
    cancellation_key: QueueCancellationKey,
}

impl QueueContext {
    /// Captures one queued request while dispatch still runs in the requestor's context.
    /// # Errors
    ///
    /// Returns a completion payload when stack classification, requestor-memory capture, or
    /// queue-context allocation fails.
    pub(super) fn capture(
        target: DispatchTarget,
        major: DispatchMajor,
    ) -> Result<Box<Self>, IrpCompletion> {
        let stack = target.current_stack().map_err(IrpCompletion::from_error)?;
        let (prepared, cancellation_key) = PreparedRequest::capture(target, stack, major)?;
        memory::boxed_try_with(|| {
            Ok(Self {
                prepared,
                cancellation_key,
            })
        })
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

    /// Returns the execution classification sealed at queue entry.
    pub(super) const fn kind(&self) -> PreparedRequestKind {
        self.prepared.kind()
    }

    /// Returns whether this queued request belongs to a cleanup cancellation identity.
    pub(super) fn matches_cancellation_context(&self, context: PVOID) -> bool {
        context.is_null() || self.cancellation_key.matches(context)
    }

    /// Borrows the opaque query-security output target.
    /// # Errors
    ///
    /// Returns an invariant error when this context is not a file-scoped query-security request.
    pub(super) fn query_security_parts(
        &mut self,
    ) -> DriverResult<(
        KernelFileObject,
        SecuritySelection,
        &mut CapturedQuerySecurityOutput,
    )> {
        let file_object = self.cancellation_key.file_object()?;
        match &mut self.prepared {
            PreparedRequest::QuerySecurity { selection, output } => {
                Ok((file_object, *selection, output))
            }
            _ => Err(DriverError::InternalInvariantViolation),
        }
    }

    /// Borrows the immutable set-security snapshot owned by this queued request.
    /// # Errors
    ///
    /// Returns an invariant error when this context is not a file-scoped set-security request.
    pub(super) fn set_security_parts(
        &self,
    ) -> DriverResult<(KernelFileObject, SecuritySelection, &[u8])> {
        let file_object = self.cancellation_key.file_object()?;
        match &self.prepared {
            PreparedRequest::SetSecurity {
                selection,
                descriptor,
            } => Ok((file_object, *selection, descriptor.as_slice())),
            _ => Err(DriverError::InternalInvariantViolation),
        }
    }
}

/// Copyable execution selector derived from a fully prepared queued request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PreparedRequestKind {
    /// One queued major function without a minor-function branch.
    Major(DispatchMajor),
    /// Directory-control request with its minor function already classified.
    DirectoryControl(DirectoryControlMinorFunction),
    /// File-system-control request with its minor function already classified.
    FileSystemControl(FileSystemControlMinorFunction),
}

/// Complete set of requests accepted by the asynchronous device lane.
#[derive(Debug)]
enum PreparedRequest {
    /// Create/open request.
    Create,
    /// Read request.
    Read,
    /// Write request.
    Write,
    /// File information query.
    QueryInformation,
    /// File information mutation.
    SetInformation,
    /// Volume information query.
    QueryVolumeInformation,
    /// Volume information mutation.
    SetVolumeInformation,
    /// Directory request with a sealed minor-function classification.
    DirectoryControl(DirectoryControlMinorFunction),
    /// File-system control with a sealed minor-function classification.
    FileSystemControl(FileSystemControlMinorFunction),
    /// Flush request.
    FlushBuffers,
    /// Extended-attribute query.
    QueryEa,
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
        target: DispatchTarget,
        stack: super::CurrentIrpStackLocation,
        major: DispatchMajor,
    ) -> Result<(Self, QueueCancellationKey), IrpCompletion> {
        let generic_key = || QueueCancellationKey::from_stack(stack);
        match major {
            DispatchMajor::Create => Ok((Self::Create, generic_key())),
            DispatchMajor::Read => Ok((Self::Read, generic_key())),
            DispatchMajor::Write => Ok((Self::Write, generic_key())),
            DispatchMajor::QueryInformation => Ok((Self::QueryInformation, generic_key())),
            DispatchMajor::SetInformation => Ok((Self::SetInformation, generic_key())),
            DispatchMajor::QueryVolumeInformation => {
                Ok((Self::QueryVolumeInformation, generic_key()))
            }
            DispatchMajor::SetVolumeInformation => Ok((Self::SetVolumeInformation, generic_key())),
            DispatchMajor::DirectoryControl => Ok((
                Self::DirectoryControl(stack.directory_control_minor()),
                generic_key(),
            )),
            DispatchMajor::FileSystemControl => {
                let minor = stack.file_system_control_minor();
                let key = match minor {
                    FileSystemControlMinorFunction::MountVolume => QueueCancellationKey::Device,
                    FileSystemControlMinorFunction::UserFsRequest
                    | FileSystemControlMinorFunction::Unsupported => generic_key(),
                };
                Ok((Self::FileSystemControl(minor), key))
            }
            DispatchMajor::FlushBuffers => Ok((Self::FlushBuffers, generic_key())),
            DispatchMajor::QueryEa => Ok((Self::QueryEa, generic_key())),
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
                    QueueCancellationKey::File(query.file_object().into()),
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
                    QueueCancellationKey::File(set.file_object().into()),
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

    /// Projects the request into the copyable worker dispatch selector.
    const fn kind(&self) -> PreparedRequestKind {
        match self {
            Self::Create => PreparedRequestKind::Major(DispatchMajor::Create),
            Self::Read => PreparedRequestKind::Major(DispatchMajor::Read),
            Self::Write => PreparedRequestKind::Major(DispatchMajor::Write),
            Self::QueryInformation => PreparedRequestKind::Major(DispatchMajor::QueryInformation),
            Self::SetInformation => PreparedRequestKind::Major(DispatchMajor::SetInformation),
            Self::QueryVolumeInformation => {
                PreparedRequestKind::Major(DispatchMajor::QueryVolumeInformation)
            }
            Self::SetVolumeInformation => {
                PreparedRequestKind::Major(DispatchMajor::SetVolumeInformation)
            }
            Self::DirectoryControl(minor) => PreparedRequestKind::DirectoryControl(*minor),
            Self::FileSystemControl(minor) => PreparedRequestKind::FileSystemControl(*minor),
            Self::FlushBuffers => PreparedRequestKind::Major(DispatchMajor::FlushBuffers),
            Self::QueryEa => PreparedRequestKind::Major(DispatchMajor::QueryEa),
            Self::SetEa => PreparedRequestKind::Major(DispatchMajor::SetEa),
            Self::QuerySecurity { .. } => PreparedRequestKind::Major(DispatchMajor::QuerySecurity),
            Self::SetSecurity { .. } => PreparedRequestKind::Major(DispatchMajor::SetSecurity),
            Self::Shutdown => PreparedRequestKind::Major(DispatchMajor::Shutdown),
        }
    }
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
    fn from_stack(stack: super::CurrentIrpStackLocation) -> Self {
        stack
            .file_object()
            .map_or(Self::Device, |file_object| Self::File(file_object.into()))
    }

    /// Compares this captured identity with an `IoCsqRemoveNextIrp` context.
    fn matches(self, context: PVOID) -> bool {
        match self {
            Self::File(file_object) => file_object.matches(context),
            Self::Device => false,
        }
    }

    /// Projects the unique FILE_OBJECT source for request execution.
    /// # Errors
    ///
    /// Returns an invariant error for a device-wide request.
    fn file_object(self) -> DriverResult<KernelFileObject> {
        match self {
            Self::File(file_object) => file_object.as_kernel_file_object(),
            Self::Device => Err(DriverError::InternalInvariantViolation),
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

    /// Reconstitutes the typed pointer while the queue-owned IRP keeps the object live.
    /// # Errors
    ///
    /// Returns an invariant error if the stored non-zero address cannot form a FILE_OBJECT.
    fn as_kernel_file_object(self) -> DriverResult<KernelFileObject> {
        let pointer = core::ptr::with_exposed_provenance_mut(self.0.get());
        KernelFileObject::from_raw(pointer).ok_or(DriverError::InternalInvariantViolation)
    }
}

/// Opaque C-owned output target for one query-security neither-I/O request.
#[derive(Debug)]
pub(crate) struct CapturedQuerySecurityOutput {
    /// Native ownership state; Rust never dereferences the opaque pending target.
    #[cfg(not(test))]
    state: QuerySecurityOutputState,
    /// Exact descriptor length fixed before the request enters the worker queue.
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

// SAFETY: The native target owns locked pages and its mapping, but neither pointer is exposed or
// dereferenced by Rust. The serialized PASSIVE_LEVEL worker consumes it through C, while Drop
// releases only an unconsumed pending target.
unsafe impl Send for CapturedQuerySecurityOutput {}

impl CapturedQuerySecurityOutput {
    /// Captures exactly the descriptor-sized output prefix in requestor process context.
    /// # Errors
    ///
    /// Returns overflow with the exact required length, a native capture failure, or an invariant
    /// error when the native ownership contract is violated.
    fn capture(
        target: DispatchTarget,
        declared_length: super::IrpBufferLength,
        selection: SecuritySelection,
    ) -> Result<Self, IrpCompletion> {
        let required = selection.query_descriptor_length();
        if declared_length.as_usize() < required {
            let completion = match IrpCompletion::security_buffer_overflow(required) {
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
            let _: DispatchTarget = target;
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
struct CapturedSetSecurityDescriptor {
    /// First byte of the native nonpaged allocation.
    address: NonNull<u8>,
    /// Exact logical descriptor length validated by the native boundary.
    length: NonZeroUsize,
}

// SAFETY: Capture returns an immutable nonpaged allocation with no requestor aliases. Ownership of
// that allocation moves with this value and Drop frees it exactly once.
unsafe impl Send for CapturedSetSecurityDescriptor {}

impl CapturedSetSecurityDescriptor {
    /// Captures, validates, and owns one requestor descriptor in a single native operation.
    /// # Errors
    ///
    /// Returns a native boundary failure or an invariant error when successful output ownership is
    /// incomplete.
    fn capture(
        target: DispatchTarget,
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
            let _: DispatchTarget = target;
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

    use super::{PreparedRequestKind, QueueContext};
    use crate::irp::{
        DirectoryControlMinorFunction, DispatchMajor, DispatchTarget,
        FileSystemControlMinorFunction, IrpCompletion, KernelIrp,
    };

    /// Builds a typed target and installs its current stack pointer.
    fn build_target(
        device: &mut wdk_sys::DEVICE_OBJECT,
        irp: &mut wdk_sys::IRP,
        stack: &mut wdk_sys::IO_STACK_LOCATION,
    ) -> Option<DispatchTarget> {
        irp.Tail
            .Overlay
            .__bindgen_anon_2
            .__bindgen_anon_1
            .CurrentStackLocation = core::ptr::from_mut(stack);
        DispatchTarget::decode(core::ptr::from_mut(device), core::ptr::from_mut(irp)).ok()
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
        if let Some(target) = target {
            let context = QueueContext::capture(target, DispatchMajor::Read);
            assert!(context.is_ok());
            if let Ok(context) = context {
                stack.MajorFunction = u8::try_from(wdk_sys::IRP_MJ_WRITE).unwrap_or_default();
                assert_eq!(u32::from(stack.MajorFunction), wdk_sys::IRP_MJ_WRITE);
                assert_eq!(
                    context.kind(),
                    PreparedRequestKind::Major(DispatchMajor::Read)
                );
            }
        }

        let mut irp = wdk_sys::IRP::default();
        let mut stack = wdk_sys::IO_STACK_LOCATION {
            MajorFunction: u8::try_from(wdk_sys::IRP_MJ_DIRECTORY_CONTROL).unwrap_or_default(),
            MinorFunction: u8::try_from(wdk_sys::IRP_MN_QUERY_DIRECTORY).unwrap_or_default(),
            FileObject: core::ptr::addr_of_mut!(file_object),
            ..wdk_sys::IO_STACK_LOCATION::default()
        };
        let target = build_target(&mut device, &mut irp, &mut stack);
        assert!(target.is_some());
        if let Some(target) = target {
            let context = QueueContext::capture(target, DispatchMajor::DirectoryControl);
            assert!(context.is_ok());
            if let Ok(context) = context {
                stack.MinorFunction = u8::MAX;
                assert_eq!(stack.MinorFunction, u8::MAX);
                assert_eq!(
                    context.kind(),
                    PreparedRequestKind::DirectoryControl(
                        DirectoryControlMinorFunction::QueryDirectory
                    )
                );
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
        if let Some(target) = target {
            let context = QueueContext::capture(target, DispatchMajor::FileSystemControl);
            assert!(context.is_ok());
            if let Ok(context) = context {
                stack.MinorFunction = u8::MAX;
                assert_eq!(stack.MinorFunction, u8::MAX);
                assert_eq!(
                    context.kind(),
                    PreparedRequestKind::FileSystemControl(
                        FileSystemControlMinorFunction::MountVolume
                    )
                );
            }
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
        if let Some(target) = target {
            let context = QueueContext::capture(target, DispatchMajor::Create);
            assert!(context.is_ok());
            if let Ok(context) = context {
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
        if let Some(target) = target {
            let context = QueueContext::capture(target, DispatchMajor::Shutdown);
            assert!(context.is_ok());
            if let Ok(context) = context {
                assert!(!context.matches_cancellation_context(
                    core::ptr::addr_of_mut!(file_object).cast::<c_void>()
                ));
            }
        }
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
        let target = build_target(&mut device, &mut irp, &mut stack);
        let kernel_irp = KernelIrp::from_raw(core::ptr::addr_of_mut!(irp));
        assert!(kernel_irp.is_some());
        let context = target.map(|target| QueueContext::capture(target, DispatchMajor::Create));
        let context = context.transpose();
        assert!(context.is_ok());
        if let (Some(kernel_irp), Ok(Some(context))) = (kernel_irp, context) {
            kernel_irp.publish_queue_context(context);
            let queued = unsafe {
                // SAFETY: This single-threaded test models a held CSQ lock until the take below.
                kernel_irp.queue_context()
            };
            assert_eq!(
                queued.kind(),
                PreparedRequestKind::Major(DispatchMajor::Create)
            );
            drop(kernel_irp.take_queue_context());

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
    /// Panics when query-security overflow or native capture failure loses its status payload.
    #[test]
    fn security_completion_statuses_preserve_required_information() {
        let overflow = IrpCompletion::security_buffer_overflow(321);
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
