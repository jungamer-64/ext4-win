//! QueryDirectory owns validated walk dependencies and unpublished output across completions.
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
/// Unique IRP owner retains traversal and record projection dependencies until completion.
#[derive(Debug)]
struct DirectoryRequestOperation {
    /// Unique completion authority retaining the handle lane.
    owned: OwnedIrp,
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
        let walk = DirectoryReadOperation::new(access.mounted_profile(), directory, query.cursor());
        Ok::<_, DriverError>((query, crypto, walk))
    })();
    let (query, crypto, walk) = match prepared {
        Ok(value) => value,
        Err(error) => return Err(AdmitOperationError::new(error, owned)),
    };
    let devices = access.storage_route();
    match memory::boxed_try_map(
        (owned, query, crypto, walk),
        |(owned, query, crypto, walk)| DirectoryRequestOperation {
            owned,
            query,
            crypto,
            devices,
            phase: DirectoryPhase::Walking(walk),
        },
    ) {
        Ok(operation) => Ok(operation),
        Err(error) => {
            let (error, (owned, _, _, _)) = error.into_parts();
            Err(AdmitOperationError::new(error, owned))
        }
    }
}

impl DirectoryRequestOperation {
    /// Reacquires namespace admission after discarding every unpublished record and cursor.
    /// The handle lane retains the directory; fresh dependencies cannot change again inside this
    /// synchronous mounted actor transition.
    fn restart(mut self: Box<Self>, access: &mut MountedVolumeAccess<'_>) -> OperationTransition {
        let (query, directory) = match DirectoryQuery::prepare(self.owned.request()) {
            Ok(prepared) => prepared,
            Err(error) => return self.fail(error),
        };
        let walk = DirectoryReadOperation::new(access.mounted_profile(), directory, query.cursor());
        self.query = query;
        self.phase = DirectoryPhase::Walking(walk);
        self.advance_mounted(CompletionEvent::Core(OperationEvent::Admitted), access)
    }
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
                    let transition = access.with_metadata_cache(|cache, access| {
                        let context = access.committed_read(cache)?;
                        Ok::<_, DriverError>(walk.advance(event, context, &mut self.crypto))
                    });
                    let transition = match transition {
                        Ok(transition) => transition,
                        Err(error) => return self.fail(error),
                    };
                    match transition {
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
                                    let read = match continuation
                                        .entry_read(access.mounted_profile(), record.node())
                                    {
                                        Ok(read) => read,
                                        Err(error) => return self.fail(error.into()),
                                    };
                                    self.phase = DirectoryPhase::Metadata {
                                        walk: continuation,
                                        record,
                                        read,
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
                            if error == Error::ReadConflict {
                                return self.restart(access);
                            }
                            return self.fail(error.into());
                        }
                    }
                }
                DirectoryPhase::Metadata { walk, record, read } => {
                    let transition = access.with_metadata_cache(|cache, access| {
                        let context = access.committed_read(cache)?;
                        Ok::<_, DriverError>(read.run(event, context, &mut self.crypto, |pass| {
                            let metadata = ext4_core::CommittedReadPass::load_node_metadata(
                                pass,
                                record.node(),
                            )?;
                            let xattrs = if self.query.needs_ea_size(metadata) {
                                Some(ext4_core::CommittedReadPass::read_xattrs(
                                    pass,
                                    record.node(),
                                )?)
                            } else {
                                None
                            };
                            Ok((metadata, xattrs))
                        }))
                    });
                    let transition = match transition {
                        Ok(transition) => transition,
                        Err(error) => return self.fail(error),
                    };
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
                        ReadTransition::Complete(Ok((metadata, xattrs))) => {
                            let ea_size = xattrs
                                .as_ref()
                                .map(crate::request::ea::information_size_from_xattrs)
                                .transpose();
                            match ea_size.and_then(|size| {
                                self.query
                                    .append_metadata(record, metadata, size.unwrap_or(0))
                            }) {
                                Ok(true) => return self.finish(None),
                                Ok(false) => self.phase = DirectoryPhase::Walking(walk),
                                Err(error) => return self.fail(error),
                            }
                        }
                        ReadTransition::Complete(Err(Error::ReadConflict)) => {
                            return self.restart(access);
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
// SAFETY: The unique IRP and reactor-owned VCB retain kernel identities across actor transfers.
unsafe impl Send for DirectoryRequestOperation {}
