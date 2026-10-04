//! Active opens and native sharing constraints have different counting domains.

use super::*;

/// Serially owned accounting from successful create admission through cleanup.
///
/// The native record excludes metadata-only opens. `active_handles` includes every admitted
/// FILE_OBJECT and is the authority for oplock, deletion and volume-lock decisions. Neither count
/// includes cleaned handles; their remaining lifetime belongs to the FILE_OBJECT reference owner.
pub(super) struct FileObjectShares {
    /// Opaque I/O Manager sharing constraints, never interpreted as a handle count.
    native: SHARE_ACCESS,
    /// Admitted FILE_OBJECTs that have not consumed cleanup or canceled-create rollback.
    active_handles: u32,
}

impl FileObjectShares {
    /// Initializes an identity before its first create admission.
    pub(super) const fn new() -> Self {
        Self {
            native: SHARE_ACCESS {
                OpenCount: 0,
                Readers: 0,
                Writers: 0,
                Deleters: 0,
                SharedRead: 0,
                SharedWrite: 0,
                SharedDelete: 0,
            },
            active_handles: 0,
        }
    }

    /// Checks operation-implied rights without admitting a returned handle.
    /// # Errors
    /// Returns the native sharing conflict before either accounting domain changes.
    #[expect(
        unsafe_code,
        reason = "the exclusive owner serializes native share validation"
    )]
    pub(super) fn check_operation(
        &mut self,
        file_object: KernelFileObject,
        access: ExistingOperationAccess,
        sharing: ShareAccess,
    ) -> DriverResult<()> {
        let status = unsafe {
            // SAFETY: The owner retains the FILE_OBJECT and exclusively owns this native record.
            // Update=false checks the operation without publishing an active open.
            ffi::IoCheckShareAccess(
                access.as_raw(),
                sharing.as_ulong(),
                file_object.as_ptr(),
                core::ptr::addr_of_mut!(self.native),
                0,
            )
        };
        if status < STATUS_SUCCESS {
            return Err(DriverError::ShareAccessConflict);
        }
        Ok(())
    }

    /// Admits one FILE_OBJECT only after both counter capacity and native sharing succeed.
    /// # Errors
    /// Returns capacity exhaustion or native sharing conflict without admitting the open.
    #[expect(
        unsafe_code,
        reason = "exclusive ownership spans native admission and infallible count publication"
    )]
    pub(super) fn open(
        &mut self,
        file_object: KernelFileObject,
        access: GrantedAccess,
        sharing: ShareAccess,
    ) -> DriverResult<NonZeroU32> {
        let next = self.next_handle_count()?;
        let status = unsafe {
            // SAFETY: The live FILE_OBJECT is not yet admitted; this exclusive owner serializes
            // native sharing. All fallible local preparation precedes this external transition.
            ffi::IoCheckShareAccess(
                access.as_raw(),
                sharing.as_ulong(),
                file_object.as_ptr(),
                core::ptr::addr_of_mut!(self.native),
                1,
            )
        };
        if status < STATUS_SUCCESS {
            return Err(DriverError::ShareAccessConflict);
        }
        self.active_handles = next.get();
        Ok(next)
    }

    /// Checks capacity before native admission can publish a share claim.
    /// # Errors
    /// Returns exhaustion before native or driver accounting changes.
    fn next_handle_count(&self) -> DriverResult<NonZeroU32> {
        self.active_handles
            .checked_add(1)
            .and_then(NonZeroU32::new)
            .ok_or(DriverError::InsufficientResources)
    }

    /// Consumes the unique cleanup/rollback obligation for one successfully admitted FILE_OBJECT.
    #[expect(
        unsafe_code,
        reason = "the handle lifecycle grants one serialized native share removal"
    )]
    pub(super) fn cleanup(&mut self, file_object: KernelFileObject) {
        let remaining = self.active_handles.checked_sub(1).unwrap_or_else(|| {
            KernelWideInconsistency::file_object_lifecycle_corruption().bugcheck()
        });
        unsafe {
            // SAFETY: Successful admission established this exact FILE_OBJECT's native claim.
            // Its lifecycle transfers cleanup once, including metadata-only native no-op claims.
            ffi::IoRemoveShareAccess(file_object.as_ptr(), core::ptr::addr_of_mut!(self.native));
        }
        self.active_handles = remaining;
    }

    /// Counts all admitted, uncleaned FILE_OBJECTs, including metadata-only opens.
    pub(super) const fn active_handle_count(&self) -> u32 {
        self.active_handles
    }
}

impl fmt::Debug for FileObjectShares {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileObjectShares")
            .field("active_handles", &self.active_handles)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Errors
    /// Returns stream-header, ledger or retained-cache-lease allocation failure.
    /// # Panics
    /// Panics if terminal writeback omits an active stream or loses it when its last handle closes.
    #[test]
    #[expect(
        unsafe_code,
        reason = "the fixture exclusively owns unpublished stream share state"
    )]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "setup returns errors while assertions verify terminal writeback retention"
    )]
    fn close_writeback_retains_active_streams_through_last_close() -> DriverResult<()> {
        let volume_stream =
            StreamContext::try_new_volume(StreamSizes::EMPTY, OperationalTrace::host_test())?;
        let mut ledger = FileControlBlockLedger::try_new()?;
        let fcb = ledger.staged_file_control_block(
            NonNull::dangling(),
            &volume_stream,
            StagedNodeStreamMetadata {
                node: NodeId::Directory(DirectoryNodeId::ROOT),
                sizes: StreamSizes::EMPTY,
            },
            OperationalTrace::host_test(),
        )?;
        let pointer = NonNull::from(fcb.as_ref().get_ref());
        unsafe {
            // SAFETY: No request or ledger entry observes this exclusively owned fixture yet.
            (*fcb.open_state.get()).shares.active_handles = 1;
        }
        ledger
            .table
            .get_mut()
            .try_push_owned(fcb)
            .map_err(|failure| failure.into_parts().0)?;
        assert!(matches!(
            ledger.prepare_volume_lock_cache_drain(),
            Err(DriverError::AccessDenied)
        ));
        let mut streams = ledger.prepare_close_cache_writeback()?;
        assert_eq!(streams.len(), 1);
        let retained_fcb = unsafe {
            // SAFETY: The ledger and snapshot both retain this live FCB at its original address.
            pointer.as_ref()
        };
        unsafe {
            // SAFETY: This single-threaded fixture exclusively owns share state while emulating cleanup.
            (*retained_fcb.open_state.get()).shares.active_handles = 0;
        }
        ledger.close(pointer);
        assert!(!ledger.is_empty());
        let stream = streams
            .pop()
            .ok_or(DriverError::InternalInvariantViolation)?;
        stream.close_writeback()?;
        drop(stream);
        assert!(ledger.is_empty());
        Ok(())
    }

    /// # Panics
    /// Panics if admission capacity depends on the native subset count or can overflow.
    #[test]
    fn admission_capacity_counts_metadata_opens_before_native_publication() {
        let mut shares = FileObjectShares::new();
        assert_eq!(shares.next_handle_count(), Ok(NonZeroU32::MIN));
        shares.active_handles = u32::MAX - 1;
        assert_eq!(shares.native.OpenCount, 0);
        assert_eq!(
            shares.next_handle_count(),
            NonZeroU32::new(u32::MAX).ok_or(DriverError::InsufficientResources)
        );
        shares.active_handles = u32::MAX;
        assert_eq!(
            shares.next_handle_count(),
            Err(DriverError::InsufficientResources)
        );
        assert_eq!(shares.active_handle_count(), u32::MAX);
        assert_eq!(shares.native.OpenCount, 0);
    }
    /// # Panics
    ///
    /// Panics when assertions or fixed test fixture assumptions fail.
    #[test]
    fn file_control_block_starts_with_empty_share_access() {
        let state = FileControlBlockOpenState::new();
        assert_eq!(state.shares.native.OpenCount, 0);
        assert_eq!(state.shares.native.Readers, 0);
        assert_eq!(state.shares.native.Writers, 0);
        assert_eq!(state.shares.native.Deleters, 0);
        assert_eq!(state.shares.native.SharedRead, 0);
        assert_eq!(state.shares.native.SharedWrite, 0);
        assert_eq!(state.shares.native.SharedDelete, 0);
    }
    /// # Panics
    ///
    /// Panics when ordinary namespace replacement can unlink an actively referenced inode.
    #[test]
    fn namespace_replacement_requires_no_active_handles() {
        let mut state = FileControlBlockOpenState::new();
        assert_eq!(state.ensure_namespace_replaceable(), Ok(()));
        state.shares.active_handles = 2;
        assert_eq!(state.shares.native.OpenCount, 0);
        assert_eq!(
            state.ensure_namespace_replaceable(),
            Err(DriverError::ShareAccessConflict)
        );
        state.shares.active_handles = 0;
        assert_eq!(state.ensure_namespace_replaceable(), Ok(()));
    }
    /// # Panics
    ///
    /// Panics when the shared FCB deletion state permits reopen or deletes before final cleanup.
    #[test]
    fn file_deletion_state_is_shared_and_waits_for_final_active_cleanup() {
        let name = Ext4Name::new(b"pending");
        assert!(name.is_ok());
        let Ok(name) = name else {
            return;
        };
        let location = OpenedLocation::try_directory_entry(DirectoryNodeId::ROOT, &name);
        assert!(location.is_ok());
        let Ok(location) = location else {
            return;
        };
        let pending = PendingFileDeletion::try_from_disposition(&location);
        assert!(pending.is_ok());
        let Ok(pending) = pending else {
            return;
        };
        let target = pending.target();
        let mut state = FileControlBlockOpenState::new();
        assert_eq!(state.deletion.ensure_openable(), Ok(()));
        assert!(!state.delete_pending());
        assert!(state.set_delete_pending(pending).is_none());
        assert_eq!(
            state.deletion.ensure_openable(),
            Err(DriverError::DeletePending)
        );
        state.shares.active_handles = 1;
        assert_eq!(
            state.cleanup_disposition(),
            FileCleanupDisposition::Retained
        );
        state.shares.active_handles = 0;
        assert_eq!(
            state.cleanup_disposition(),
            FileCleanupDisposition::Delete(target)
        );
        let completed = state.complete_delete(target);
        assert_eq!(completed.target(), target);
        assert!(state.abort_cleanup_delete(target).is_none());
        assert!(state.delete_pending());
        assert_eq!(
            state.deletion.ensure_openable(),
            Err(DriverError::DeletePending)
        );
    }
}
