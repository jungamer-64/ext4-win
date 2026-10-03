//! Reversible PnP create closure with cache and journal durability before lower delegation.
//! The ext4 recovery marker remains set, so cancellation needs no disk rewrite to resume.

use super::*;
use crate::kernel::stream::QueryRemovalPreparation;
use crate::state::PreparedStreamCacheDrain;

/// Independent journal barriers before cache capture and after paging writeback.
#[derive(Clone, Copy, Debug)]
enum QueryBarrier {
    /// Previously admitted creates can still publish FILE_OBJECTs.
    BeforeCache,
    /// Cache drain has finished; its paging mutations must checkpoint before device flush.
    AfterCache,
}

/// Sole query-remove preparation and IRP ownership at each actor suspension boundary.
#[derive(Debug)]
enum QueryState {
    /// No native create-admission effect has happened yet.
    Ready(OwnedIrp),
    /// Create admission is closed while journal work reaches a known durable endpoint.
    Waiting {
        /// Original request retained through the barrier.
        owned: OwnedIrp,
        /// Unpublished reversible gate, automatically released on failure.
        preparation: QueryRemovalPreparation,
        /// Distinct reason for this journal drain.
        barrier: QueryBarrier,
    },
    /// One worker owns the current cache stream; this state retains the rest of the plan.
    Draining {
        /// Original request retained until lower PnP delegation.
        owned: OwnedIrp,
        /// Query-specific create gate retained while Cc/MM may reenter.
        preparation: QueryRemovalPreparation,
        /// Remaining retained streams and accepted completion count.
        drain: PreparedStreamCacheDrain,
    },
    /// A referenced storage route owns one flush; no recovery marker is cleared.
    Flushing {
        /// Original request retained until all durability effects finish.
        owned: OwnedIrp,
        /// Query-specific create gate remains unpublished.
        preparation: QueryRemovalPreparation,
        /// Exact target flushed, including an independently durable external journal.
        target: ext4_core::StorageTarget,
        /// Expected lower request identity.
        expected: StorageRequestIdentity,
    },
    /// Terminal completion or original-IRP lower submission owns the request.
    Terminal,
}

/// A query never consumes mounted close authority or changes the actor's lifecycle state.
#[derive(Debug)]
struct QueryRemoveOperation {
    /// Exclusive preparation and IRP authority.
    state: QueryState,
}

/// Allocates one query-remove operation before any reversible gate or media effect.
/// # Errors
/// Returns the retained IRP on allocation failure.
pub(crate) fn query_remove(
    owned: OwnedIrp,
) -> Result<Box<dyn CompletionOperation>, AdmitOperationError> {
    memory::boxed_try_map(owned, |owned| QueryRemoveOperation {
        state: QueryState::Ready(owned),
    })
    .map(|operation| -> Box<dyn CompletionOperation> { operation })
    .map_err(|failure| {
        let (error, owned) = failure.into_parts();
        AdmitOperationError::new(error, owned)
    })
}

impl QueryRemoveOperation {
    /// Waits without retaining actor borrows; dropping preparation can undo only this query.
    fn wait(
        mut self: Box<Self>,
        owned: OwnedIrp,
        preparation: QueryRemovalPreparation,
        barrier: QueryBarrier,
    ) -> OperationTransition {
        self.state = QueryState::Waiting {
            owned,
            preparation,
            barrier,
        };
        OperationTransition::Wait {
            condition: WaitCondition::JournalClean,
            suspended: self,
        }
    }

    /// Flushes and purges retained cache streams before the final journal barrier.
    fn drain(
        mut self: Box<Self>,
        owned: OwnedIrp,
        preparation: QueryRemovalPreparation,
        mut drain: PreparedStreamCacheDrain,
        access: &MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        if let Some(stream) = drain.next() {
            self.state = QueryState::Draining {
                owned,
                preparation,
                drain,
            };
            return OperationTransition::SubmitPassiveWork {
                work: crate::irp::PassiveWork::drain_for_volume_lock(stream),
                suspended: self,
            };
        }
        let result = drain
            .into_completed()
            .and_then(|completed| access.finish_volume_lock_cache_drain(completed));
        match result {
            Ok(()) => self.wait(owned, preparation, QueryBarrier::AfterCache),
            Err(error) => OperationTransition::Complete(owned.prepare_result(Err(error))),
        }
    }

    /// Flushes each independently durable storage target after every journal mutation drained.
    fn flush(
        mut self: Box<Self>,
        owned: OwnedIrp,
        preparation: QueryRemovalPreparation,
        target: ext4_core::StorageTarget,
        access: &MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        let request = StorageRequest::Flush { target };
        let expected = StorageRequestIdentity::from_request(&request);
        self.state = QueryState::Flushing {
            owned,
            preparation,
            target,
            expected,
        };
        OperationTransition::SubmitLower {
            devices: access.storage_route(),
            request,
            suspended: self,
        }
    }
}

impl MountedVolumeOperation for QueryRemoveOperation {
    fn advance_mounted(
        mut self: Box<Self>,
        event: CompletionEvent,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        let state = core::mem::replace(&mut self.state, QueryState::Terminal);
        match (state, event) {
            (QueryState::Ready(owned), CompletionEvent::Core(OperationEvent::Admitted)) => {
                match access.prepare_query_removal() {
                    Ok(preparation) => self.wait(owned, preparation, QueryBarrier::BeforeCache),
                    Err(error) => OperationTransition::Complete(owned.prepare_result(Err(error))),
                }
            }
            (
                QueryState::Waiting {
                    owned,
                    preparation,
                    barrier,
                },
                CompletionEvent::Core(OperationEvent::BarrierReleased(permit)),
            ) => {
                if permit.into_identity() != 1 {
                    crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption().bugcheck();
                }
                match barrier {
                    QueryBarrier::BeforeCache => match access.prepare_query_removal_cache_drain() {
                        Ok(drain) => self.drain(owned, preparation, drain, access),
                        Err(error) => {
                            OperationTransition::Complete(owned.prepare_result(Err(error)))
                        }
                    },
                    QueryBarrier::AfterCache => {
                        if let Err(error) = access.authorize_query_removal() {
                            return OperationTransition::Complete(owned.prepare_result(Err(error)));
                        }
                        self.flush(
                            owned,
                            preparation,
                            access.mounted_profile().journal_target(),
                            access,
                        )
                    }
                }
            }
            (
                QueryState::Draining {
                    owned,
                    preparation,
                    mut drain,
                },
                CompletionEvent::PassiveCompleted(
                    crate::irp::PassiveWorkCompletion::DrainForVolumeLock(result),
                ),
            ) => match result.and_then(|completed| drain.record_completion(completed)) {
                Ok(()) => self.drain(owned, preparation, drain, access),
                Err(error) => {
                    record_cache_coherency_failure(error, access);
                    OperationTransition::Complete(owned.prepare_result(Err(error)))
                }
            },
            (
                QueryState::Flushing {
                    owned,
                    preparation,
                    target,
                    expected,
                },
                CompletionEvent::Core(OperationEvent::StorageCompleted(completion)),
            ) => {
                if let Err(error) = expected.complete(completion) {
                    return OperationTransition::Complete(
                        owned.prepare_result(Err(DriverError::from(error))),
                    );
                }
                if target != ext4_core::StorageTarget::Filesystem {
                    return self.flush(
                        owned,
                        preparation,
                        ext4_core::StorageTarget::Filesystem,
                        access,
                    );
                }
                let storage = access.storage_access();
                let lower = access.storage_route().filesystem_control_device();
                if let Err(error) = access
                    .authorize_query_removal()
                    .and_then(|()| preparation.publish())
                {
                    return OperationTransition::Complete(owned.prepare_result(Err(error)));
                }
                OperationTransition::ForwardQueryRemove(
                    owned.prepare_query_remove_forward(lower, storage),
                )
            }
            (
                QueryState::Ready(owned)
                | QueryState::Waiting { owned, .. }
                | QueryState::Draining { owned, .. }
                | QueryState::Flushing { owned, .. },
                CompletionEvent::Core(OperationEvent::CancelRequested),
            ) => OperationTransition::Complete(
                owned.prepare_result(Err(DriverError::from(Error::OperationCancelled))),
            ),
            (QueryState::Waiting { owned, .. }, CompletionEvent::VolumeFailed(error)) => {
                OperationTransition::Complete(owned.prepare_result(Err(error)))
            }
            _ => {
                crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                    .bugcheck()
            }
        }
    }

    fn record_mounted_storage_failure(
        &mut self,
        failure: StorageFailureClass,
        access: &mut MountedVolumeAccess<'_>,
    ) {
        if failure.is_durability_unknown() {
            access.record_durability_unknown();
        }
    }
}

impl_mounted_operation_adapter!(QueryRemoveOperation);

#[expect(
    unsafe_code,
    reason = "the reactor and owned native envelopes retain all query gate, stream, and IRP identities through terminal ownership transfer"
)]
// SAFETY: No actor borrow or thread-affine native resource crosses a suspension boundary.
unsafe impl Send for QueryRemoveOperation {}
