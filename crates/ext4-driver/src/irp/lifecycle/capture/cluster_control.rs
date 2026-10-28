//! Requestor-context handle references for physical cluster controls.

use super::*;

/// A referenced native object owns lifetime, while the decoded kind limits its admitted use.
#[derive(Debug)]
#[cfg_attr(
    test,
    expect(
        dead_code,
        reason = "successful embedded-handle capture requires the native Object Manager boundary"
    )
)]
pub(crate) enum PreparedClusterControl {
    /// Exact regular-file movement request selected through a privileged direct-volume handle.
    Move {
        /// Reference captured in the issuing process and retained through terminal acknowledgment.
        file: CapturedFileReference,
        /// File-relative virtual cluster coordinate.
        vcn: u64,
        /// Allocation-origin-relative physical destination.
        lcn: ext4_core::ClusterAddress,
        /// Nonzero allocation cluster count.
        count: ext4_core::ClusterCount,
        /// Granted rights are relevant for encrypted-file handle admission.
        granted: u32,
    },
    /// Cluster protection lasts until this FILE_OBJECT consumes cleanup.
    Mark {
        /// Optional same-volume DASD handle reference.
        volume: Option<CapturedFileReference>,
        /// Zero is a valid no-op; one enables protection idempotently.
        protect: bool,
    },
}

/// Object Manager reference whose handle was resolved in its original process.
#[derive(Debug)]
pub(crate) struct CapturedFileReference {
    /// Stable native identity; Drop owns the corresponding reference release.
    file: KernelFileObject,
}

impl CapturedFileReference {
    /// Restricts native field access to the explicit object reference's borrow lifetime.
    pub(crate) fn with_file<R>(
        &self,
        operation: impl for<'view> FnOnce(super::super::super::ActiveFileObject<'view>) -> R,
    ) -> R {
        operation(super::super::super::ActiveFileObject {
            address: self.file,
            owner: core::marker::PhantomData,
        })
    }
}

#[cfg(not(test))]
#[expect(
    unsafe_code,
    reason = "this unique value owns exactly the Object Manager reference captured before deferral"
)]
impl Drop for CapturedFileReference {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: Native capture transferred one successful FILE_OBJECT reference to this value.
            ffi::ObfDereferenceObject(self.file.as_ptr().cast());
        }
    }
}

#[expect(
    unsafe_code,
    reason = "a referenced FILE_OBJECT has stable identity until its sole reference owner drops"
)]
// SAFETY: The owning value moves without native field access; every observation is lifetime bounded.
unsafe impl Send for CapturedFileReference {}

impl PreparedClusterControl {
    /// Captures handle identity before queue insertion and seals all meaningful scalar fields.
    /// # Errors
    /// Returns malformed ABI, unavailable handle, object type/access or unsupported marking flags.
    #[cfg_attr(
        not(test),
        expect(
            unsafe_code,
            reason = "native capture consumes only the retained original IRP and initialized scalar outputs"
        )
    )]
    pub(super) fn capture(
        target: &ActiveIrp<'_>,
        code: super::super::super::FsControlCode,
    ) -> DriverResult<Self> {
        #[cfg(not(test))]
        {
            let mut handle = core::ptr::null_mut();
            let (mut vcn, mut lcn) = (0, 0);
            let (mut count, mut source_info, mut flags, mut granted) = (0, 0, 0, 0);
            let status = unsafe {
                // SAFETY: Capture runs synchronously in the requestor process. Outputs are uniquely
                // borrowed stack storage; the captured handle is not used outside this dispatch context.
                ffi::ext4win_capture_cluster_control(
                    target.irp.as_ptr(),
                    &raw mut handle,
                    &raw mut vcn,
                    &raw mut lcn,
                    &raw mut count,
                    &raw mut source_info,
                    &raw mut flags,
                )
            };
            if status < wdk_sys::STATUS_SUCCESS {
                return Err(DriverError::ClusterControlCaptureFailed(status));
            }
            let protect = match code {
                super::super::super::FsControlCode::MarkHandle => {
                    mark_protection(source_info, flags)?
                }
                super::super::super::FsControlCode::MoveFile => false,
                _ => return Err(DriverError::InvalidDeviceRequest),
            };
            let mut file = core::ptr::null_mut();
            if !handle.is_null() {
                let status = unsafe {
                    // SAFETY: This call remains on the captured IRP's original requestor thread;
                    // Rust admitted the complete semantics before acquiring an object reference.
                    ffi::ext4win_reference_cluster_file(
                        handle,
                        target.requestor_mode(),
                        &raw mut file,
                        &raw mut granted,
                    )
                };
                if status < wdk_sys::STATUS_SUCCESS {
                    return Err(DriverError::ClusterControlCaptureFailed(status));
                }
            }
            let file = unsafe {
                // SAFETY: Success transferred the reference; a null identity means optional MARK volume.
                KernelFileObject::from_raw(file)
            }
            .map(|file| CapturedFileReference { file });
            match code {
                super::super::super::FsControlCode::MoveFile => Ok(Self::Move {
                    file: file.ok_or(DriverError::InvalidParameter)?,
                    vcn,
                    lcn: ext4_core::ClusterAddress::new(lcn),
                    count: ext4_core::ClusterCount::new(u64::from(count))?,
                    granted,
                }),
                super::super::super::FsControlCode::MarkHandle => Ok(Self::Mark {
                    volume: file,
                    protect,
                }),
                _ => Err(DriverError::InvalidDeviceRequest),
            }
        }
        #[cfg(test)]
        {
            let _input = (target, code);
            Err(DriverError::NotSupported)
        }
    }
}

/// Selects supported marking semantics independently from ABI capture and handle retention.
/// # Errors
/// Returns unsupported for source annotations or flags without an implemented filesystem effect.
fn mark_protection(source_info: u32, flags: u32) -> DriverResult<bool> {
    if source_info != 0 || flags & !wdk_sys::MARK_HANDLE_PROTECT_CLUSTERS != 0 {
        return Err(DriverError::NotSupported);
    }
    Ok(flags & wdk_sys::MARK_HANDLE_PROTECT_CLUSTERS != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Panics
    /// Fails if unsupported marking semantics become a silent no-op.
    #[test]
    fn supported_marking_requires_complete_semantic_admission() {
        assert_eq!(mark_protection(0, 0), Ok(false));
        assert_eq!(
            mark_protection(0, wdk_sys::MARK_HANDLE_PROTECT_CLUSTERS),
            Ok(true)
        );
        assert_eq!(mark_protection(1, 0), Err(DriverError::NotSupported));
        assert_eq!(mark_protection(0, 2), Err(DriverError::NotSupported));
        assert_eq!(mark_protection(0, u32::MAX), Err(DriverError::NotSupported));
    }
}
