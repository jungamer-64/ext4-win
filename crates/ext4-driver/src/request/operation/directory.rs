//! QueryDirectory owns validated walk dependencies and unpublished output across completions.
use super::*;
use crate::request::file_info::{DirectoryQuery, DirectoryQueryStart, DirectorySelection};
use ext4_core::{DirectoryReadOperation, DirectoryReadTransition};

/// The next event belongs exclusively to the comparison read, traversal, or one record's metadata.
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "this state resides in the request allocation; per-entry boxing would add hot-path allocations"
)]
enum DirectoryPhase {
    /// The handle's first query reads the directory comparison before capturing its expression.
    Comparison {
        /// Directory whose comparison selects the expression's matching.
        directory: ext4_core::DirectoryNodeId,
        /// Unfinished inode and xattr reads.
        read: EpochReadOperation,
    },
    /// Core traversal owns all decoded progress.
    Walking {
        /// Private packing progress and the captured search expression.
        query: DirectoryQuery,
        /// Decoded traversal state.
        walk: DirectoryReadOperation,
    },
    /// Traversal is paused until this record's metadata has completed.
    Metadata {
        /// Private packing progress and the captured search expression.
        query: DirectoryQuery,
        /// Decoded traversal resumes only after the reserved record is packed.
        walk: DirectoryReadOperation,
        /// Matching name with capacity reserved in the request output.
        record: ext4_core::ScannedDirectoryEntry,
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
    /// Identifies which consumer owns the next event.
    phase: DirectoryPhase,
}

/// Selects the first phase from the handle's expression state.
/// # Errors
/// Returns captured directory-query or handle validation failures.
fn start_phase(
    owned: &mut OwnedIrp,
    access: &MountedVolumeAccess<'_>,
) -> DriverResult<DirectoryPhase> {
    Ok(match DirectoryQuery::start(owned.request())? {
        DirectoryQueryStart::Prepared(query) => walking(query, access),
        DirectoryQueryStart::ComparisonRequired(directory) => DirectoryPhase::Comparison {
            directory,
            read: EpochReadOperation::new(access.mounted_profile()),
        },
    })
}

/// Starts traversal from the query's private continuation.
fn walking(query: DirectoryQuery, access: &MountedVolumeAccess<'_>) -> DirectoryPhase {
    let walk =
        DirectoryReadOperation::new(access.mounted_profile(), query.directory(), query.cursor());
    DirectoryPhase::Walking { query, walk }
}

/// Admits a directory read into the existing per-handle serialization lane.
/// # Errors
/// Returns admission failures together with the still-owned IRP.
pub(crate) fn query_directory(
    mut owned: OwnedIrp,
    access: &mut MountedVolumeAccess<'_>,
) -> Result<Box<dyn CompletionOperation>, AdmitOperationError> {
    let prepared = (|| {
        let phase = start_phase(&mut owned, access)?;
        let crypto = access.new_crypto_operation()?;
        Ok::<_, DriverError>((phase, crypto))
    })();
    let (phase, crypto) = match prepared {
        Ok(value) => value,
        Err(error) => return Err(AdmitOperationError::new(error, owned)),
    };
    let devices = access.storage_route();
    match memory::boxed_try_map((owned, phase, crypto), |(owned, phase, crypto)| {
        DirectoryRequestOperation {
            owned,
            crypto,
            devices,
            phase,
        }
    }) {
        Ok(operation) => Ok(operation),
        Err(error) => {
            let (error, (owned, _, _)) = error.into_parts();
            Err(AdmitOperationError::new(error, owned))
        }
    }
}

impl DirectoryRequestOperation {
    /// Reacquires namespace admission after discarding every unpublished record and cursor.
    /// The handle lane retains the directory; fresh dependencies cannot change again inside this
    /// synchronous mounted actor transition.
    ///
    /// # Errors
    /// Returns a captured directory-query or handle validation failure before traversal resumes.
    fn restart(&mut self, access: &mut MountedVolumeAccess<'_>) -> DriverResult<()> {
        self.phase = start_phase(&mut self.owned, access)?;
        Ok(())
    }
    /// Drops unpublished packing progress and completes the owned request with its error.
    fn fail(self: Box<Self>, error: DriverError) -> OperationTransition {
        OperationTransition::Complete(self.owned.prepare_result(Err(error)))
    }
    /// Copies output and publishes the continuation before releasing IRP ownership.
    fn finish(
        mut self: Box<Self>,
        query: DirectoryQuery,
        end: Option<ext4_core::DirectoryScanCursor>,
    ) -> OperationTransition {
        let result = query.finish(self.owned.request(), end);
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
                DirectoryPhase::Comparison { directory, read } => {
                    let transition = access.with_metadata_cache(|cache, access| {
                        let context = access.committed_read(cache)?;
                        Ok::<_, DriverError>(read.run(event, context, &mut self.crypto, |pass| {
                            crate::metadata::DirectoryNameComparison::observe(pass, directory)
                        }))
                    });
                    let transition = match transition {
                        Ok(transition) => transition,
                        Err(error) => return self.fail(error),
                    };
                    match transition {
                        ReadTransition::SubmitLower { request, suspended } => {
                            self.phase = DirectoryPhase::Comparison {
                                directory,
                                read: suspended,
                            };
                            return OperationTransition::SubmitLower {
                                devices: self.devices,
                                request,
                                suspended: self,
                            };
                        }
                        ReadTransition::Complete(Ok((casefold, marker))) => {
                            let query = crate::metadata::DirectoryNameComparison::decode(
                                casefold,
                                marker.as_ref(),
                            )
                            .and_then(|comparison| {
                                DirectoryQuery::capture(self.owned.request(), comparison)
                            });
                            match query {
                                Ok(query) => self.phase = walking(query, access),
                                Err(error) => return self.fail(error),
                            }
                        }
                        ReadTransition::Complete(Err(Error::ReadConflict)) => {
                            if let Err(error) = self.restart(access) {
                                return self.fail(error);
                            }
                        }
                        ReadTransition::Complete(Err(error)) => return self.fail(error.into()),
                    }
                }
                DirectoryPhase::Walking { mut query, walk } => {
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
                            self.phase = DirectoryPhase::Walking {
                                query,
                                walk: suspended,
                            };
                            return OperationTransition::SubmitLower {
                                devices: self.devices,
                                request,
                                suspended: self,
                            };
                        }
                        DirectoryReadTransition::Entry {
                            entry,
                            continuation,
                        } if query.needs_metadata() => {
                            let read = match continuation
                                .entry_read(access.mounted_profile(), *entry.entry().node())
                            {
                                Ok(read) => read,
                                Err(error) => return self.fail(error.into()),
                            };
                            self.phase = DirectoryPhase::Metadata {
                                query,
                                walk: continuation,
                                record: entry,
                                read,
                            };
                        }
                        DirectoryReadTransition::Entry {
                            entry,
                            continuation,
                        } => match query.select(entry, None) {
                            Ok(DirectorySelection::Skip) => {
                                self.phase = DirectoryPhase::Walking {
                                    query,
                                    walk: continuation,
                                }
                            }
                            Ok(DirectorySelection::Full) => return self.finish(query, None),
                            Ok(DirectorySelection::Record(record)) => {
                                match query.append_name(record) {
                                    Ok(true) => return self.finish(query, None),
                                    Ok(false) => {
                                        self.phase = DirectoryPhase::Walking {
                                            query,
                                            walk: continuation,
                                        }
                                    }
                                    Err(error) => return self.fail(error),
                                }
                            }
                            Err(error) => return self.fail(error),
                        },
                        DirectoryReadTransition::Complete(Ok(cursor)) => {
                            return self.finish(query, Some(cursor));
                        }
                        DirectoryReadTransition::Complete(Err(error)) => {
                            if error == Error::ReadConflict {
                                if let Err(error) = self.restart(access) {
                                    return self.fail(error);
                                }
                            } else {
                                return self.fail(error.into());
                            }
                        }
                    }
                }
                DirectoryPhase::Metadata {
                    mut query,
                    walk,
                    record,
                    read,
                } => {
                    let directory = query.directory();
                    let transition = access.with_metadata_cache(|cache, access| {
                        let context = access.committed_read(cache)?;
                        Ok::<_, DriverError>(read.run(event, context, &mut self.crypto, |pass| {
                            let metadata = ext4_core::CommittedReadPass::load_node_metadata(
                                pass,
                                *record.entry().node(),
                            )?;
                            let xattrs = ext4_core::CommittedReadPass::read_xattrs(
                                pass,
                                *record.entry().node(),
                            )?;
                            let alias = crate::short_name::visible_alias(
                                pass,
                                directory,
                                record.entry().name(),
                                *record.entry().node(),
                            );
                            if let Err(DriverError::Core(error)) = alias {
                                return Err(error);
                            }
                            Ok((metadata, xattrs, alias))
                        }))
                    });
                    let transition = match transition {
                        Ok(transition) => transition,
                        Err(error) => return self.fail(error),
                    };
                    match transition {
                        ReadTransition::SubmitLower { request, suspended } => {
                            self.phase = DirectoryPhase::Metadata {
                                query,
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
                        ReadTransition::Complete(Ok((metadata, xattrs, alias))) => {
                            let alias = match alias {
                                Ok(alias) => alias,
                                Err(error) => return self.fail(error),
                            };
                            let record = match query.select(record, alias) {
                                Ok(DirectorySelection::Skip) => {
                                    self.phase = DirectoryPhase::Walking { query, walk };
                                    event = OperationEvent::Admitted;
                                    continue;
                                }
                                Ok(DirectorySelection::Full) => return self.finish(query, None),
                                Ok(DirectorySelection::Record(record)) => record,
                                Err(error) => return self.fail(error),
                            };
                            let metadata = match crate::metadata::WindowsNodeMetadata::from_ext4(
                                metadata, &xattrs,
                            ) {
                                Ok(metadata) => metadata,
                                Err(error) => return self.fail(error),
                            };
                            let ea_size = if query.needs_ea_size(metadata) {
                                crate::request::ea::information_size_from_xattrs(&xattrs).map(Some)
                            } else {
                                Ok(None)
                            };
                            match ea_size.and_then(|size| {
                                query.append_metadata(record, metadata, size.unwrap_or(0))
                            }) {
                                Ok(true) => return self.finish(query, None),
                                Ok(false) => self.phase = DirectoryPhase::Walking { query, walk },
                                Err(error) => return self.fail(error),
                            }
                        }
                        ReadTransition::Complete(Err(Error::ReadConflict)) => {
                            if let Err(error) = self.restart(access) {
                                return self.fail(error);
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
// SAFETY: The unique IRP and reactor-owned VCB retain kernel identities across actor transfers.
unsafe impl Send for DirectoryRequestOperation {}
