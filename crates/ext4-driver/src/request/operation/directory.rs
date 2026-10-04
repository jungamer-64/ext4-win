//! QueryDirectory owns its epoch, walk and packed output across every lower completion.
use super::*;
use crate::request::file_info::{DirectoryQuery, DirectoryRecord, DirectorySelection};
use ext4_core::{DirectoryReadOperation, DirectoryReadTransition};

/// The next event belongs exclusively to traversal or to one reserved record's metadata.
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "this state resides in the request allocation; per-entry boxing would add hot-path allocations"
)]
enum DirectoryPhase {
    /// Core traversal owns all decoded progress.
    Walking(DirectoryReadOperation),
    /// Traversal is paused until this record's metadata has completed.
    Metadata {
        /// Decoded traversal resumes only after the reserved record is packed.
        walk: DirectoryReadOperation,
        /// Matching name with capacity reserved in the request output.
        record: DirectoryRecord,
        /// Only this record's unfinished metadata reads are retained.
        read: EpochReadOperation,
    },
    /// The phase is being consumed for completion or replacement.
    Terminal,
}
/// Unique IRP owner and its immutable epoch lease survive every lower completion.
#[derive(Debug)]
struct DirectoryRequestOperation {
    /// Unique completion authority retaining the handle lane.
    owned: OwnedIrp,
    /// Snapshot lease remains valid through copy and cursor publication.
    epoch: EpochLease,
    /// Mounted lower targets retained by the reactor.
    devices: MountedStorageRoute,
    /// Encryption objects persist across all read suspensions.
    crypto: CngOperation,
    /// Private packing progress and the initial search expression.
    query: DirectoryQuery,
    /// Identifies which consumer owns the next event.
    phase: DirectoryPhase,
}

/// Admits a directory read into the existing per-handle serialization lane.
/// # Errors
/// Returns admission failures together with the still-owned IRP.
pub(crate) fn query_directory(
    mut owned: OwnedIrp,
    access: &mut MountedVolumeAccess<'_>,
) -> Result<Box<dyn CompletionOperation>, AdmitOperationError> {
    let prepared = (|| {
        let (query, directory) = DirectoryQuery::prepare(owned.request())?;
        let crypto = access.new_crypto_operation()?;
        let epoch = access.acquire_epoch()?;
        let walk = DirectoryReadOperation::new(access.mounted_profile(), directory, query.cursor());
        Ok::<_, DriverError>((query, crypto, epoch, walk))
    })();
    let (query, crypto, epoch, walk) = match prepared {
        Ok(value) => value,
        Err(error) => return Err(AdmitOperationError::new(error, owned)),
    };
    let devices = access.storage_route();
    match memory::boxed_try_map(
        (owned, query, crypto, epoch, walk),
        |(owned, query, crypto, epoch, walk)| DirectoryRequestOperation {
            owned,
            query,
            crypto,
            epoch,
            devices,
            phase: DirectoryPhase::Walking(walk),
        },
    ) {
        Ok(operation) => Ok(operation),
        Err(error) => {
            let (error, (owned, _, _, _, _)) = error.into_parts();
            Err(AdmitOperationError::new(error, owned))
        }
    }
}

impl DirectoryRequestOperation {
    /// Drops unpublished packing progress and completes the owned request with its error.
    fn fail(self: Box<Self>, error: DriverError) -> OperationTransition {
        OperationTransition::Complete(self.owned.prepare_result(Err(error)))
    }
    /// Copies output and publishes the continuation before releasing IRP ownership.
    fn finish(
        mut self: Box<Self>,
        end: Option<ext4_core::DirectoryScanCursor>,
    ) -> OperationTransition {
        let result = self.query.finish(self.owned.request(), end);
        OperationTransition::Complete(self.owned.prepare_result(result))
    }
}
impl_mounted_operation_adapter!(DirectoryRequestOperation);
impl MountedVolumeOperation for DirectoryRequestOperation {
    fn advance_mounted(
        mut self: Box<Self>,
        event: CompletionEvent,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        let mut event = event.into_core();
        if matches!(event, OperationEvent::CancelRequested) {
            return self.fail(DriverError::from(Error::OperationCancelled));
        }
        loop {
            match core::mem::replace(&mut self.phase, DirectoryPhase::Terminal) {
                DirectoryPhase::Walking(walk) => {
                    match access.with_metadata_cache(|cache, _access| {
                        walk.advance(event, cache.access(self.epoch.epoch()), &mut self.crypto)
                    }) {
                        DirectoryReadTransition::SubmitLower { request, suspended } => {
                            self.phase = DirectoryPhase::Walking(suspended);
                            return OperationTransition::SubmitLower {
                                devices: self.devices,
                                request,
                                suspended: self,
                            };
                        }
                        DirectoryReadTransition::Entry {
                            entry,
                            continuation,
                        } => match self.query.select(entry) {
                            Ok(DirectorySelection::Skip) => {
                                self.phase = DirectoryPhase::Walking(continuation)
                            }
                            Ok(DirectorySelection::Full) => return self.finish(None),
                            Ok(DirectorySelection::Record(record)) => {
                                if self.query.needs_metadata() {
                                    self.phase = DirectoryPhase::Metadata {
                                        walk: continuation,
                                        record,
                                        read: EpochReadOperation::new(access.mounted_profile()),
                                    };
                                } else {
                                    match self.query.append_name(record) {
                                        Ok(true) => return self.finish(None),
                                        Ok(false) => {
                                            self.phase = DirectoryPhase::Walking(continuation)
                                        }
                                        Err(error) => return self.fail(error),
                                    }
                                }
                            }
                            Err(error) => return self.fail(error),
                        },
                        DirectoryReadTransition::Complete(Ok(cursor)) => {
                            return self.finish(Some(cursor));
                        }
                        DirectoryReadTransition::Complete(Err(error)) => {
                            return self.fail(error.into());
                        }
                    }
                }
                DirectoryPhase::Metadata { walk, record, read } => {
                    let transition = access.with_metadata_cache(|cache, _access| {
                        read.run(
                            event,
                            cache.access(self.epoch.epoch()),
                            &mut self.crypto,
                            |pass| {
                                ext4_core::CommittedReadPass::load_node_metadata(
                                    pass,
                                    record.node(),
                                )
                            },
                        )
                    });
                    match transition {
                        ReadTransition::SubmitLower { request, suspended } => {
                            self.phase = DirectoryPhase::Metadata {
                                walk,
                                record,
                                read: suspended,
                            };
                            return OperationTransition::SubmitLower {
                                devices: self.devices,
                                request,
                                suspended: self,
                            };
                        }
                        ReadTransition::Complete(Ok(metadata)) => {
                            match self.query.append_metadata(record, metadata) {
                                Ok(true) => return self.finish(None),
                                Ok(false) => self.phase = DirectoryPhase::Walking(walk),
                                Err(error) => return self.fail(error),
                            }
                        }
                        ReadTransition::Complete(Err(error)) => return self.fail(error.into()),
                    }
                }
                DirectoryPhase::Terminal => {
                    return self.fail(DriverError::InternalInvariantViolation);
                }
            }
            event = OperationEvent::Admitted;
        }
    }
    fn record_mounted_storage_failure(
        &mut self,
        failure: StorageFailureClass,
        access: &mut MountedVolumeAccess<'_>,
    ) {
        match failure {
            StorageFailureClass::ReadUnreliable => access.record_read_unreliable(),
            StorageFailureClass::DurabilityUnknown { .. } => access.record_durability_unknown(),
            StorageFailureClass::Terminal => {}
        }
    }
}
#[expect(
    unsafe_code,
    reason = "the reactor retains the VCB and serializes this IRP's handle lane through completion"
)]
// SAFETY: The unique IRP and epoch lease retain all kernel identities across actor transfers.
unsafe impl Send for DirectoryRequestOperation {}
