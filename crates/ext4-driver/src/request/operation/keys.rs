//! Mount-key changes own scheduler grants and namespace exclusion, never lower-storage requests.

use super::*;
use ext4_core::{PreparedKeyChange, ReservedKeyChange, ResolvedKeyChange};

/// Distinct native authority needed by each mount-key operation.
#[derive(Debug)]
enum KeyRequest {
    /// Operation-owned cryptographic objects derive and authenticate the supplied key.
    Add(CngOperation),
    /// Native namespace exclusion remains held through removal publication or abort.
    Remove(crate::kernel::stream::KeyRemovalLease),
}

impl KeyRequest {
    /// Native authorization class of this retained request.
    const fn control(&self) -> crate::irp::PreparedKeyControl {
        match self {
            Self::Add(_) => crate::irp::PreparedKeyControl::Add,
            Self::Remove(_) => crate::irp::PreparedKeyControl::Remove,
        }
    }
}

/// Owned top-level request and acknowledgment retained until its key snapshot is published.
#[derive(Debug)]
struct KeyContext {
    /// Unique upper completion authority.
    owned: OwnedIrp,
    /// Native resources that cannot retire before publication or cancellation.
    request: KeyRequest,
    /// Prevalidated output size and success status.
    completion: IrpCompletion,
}

/// Explicit key publication protocol; no state carries a storage-transfer capability.
#[derive(Debug)]
#[cfg_attr(
    not(test),
    expect(
        clippy::missing_docs_in_private_items,
        reason = "variant contracts and owned protocol types define the retained fields without duplicating their documentation"
    )
)]
enum KeyState {
    /// Captured request awaiting its first scheduler turn.
    Ready {
        owned: OwnedIrp,
        request: KeyRequest,
    },
    /// Snapshot awaits the exclusive key-set resource intent.
    Intent {
        context: KeyContext,
        resolved: ResolvedKeyChange,
    },
    /// Reserved key successor awaits serialization with filesystem epoch replacements.
    Commit {
        context: KeyContext,
        reserved: ReservedKeyChange,
    },
    /// Every fallible preparation finished; cancellation may still discard the successor.
    Visibility {
        context: KeyContext,
        prepared: PreparedKeyChange,
        slot: EpochPublicationSlot,
    },
    /// The matching visibility grant authorizes the atomic consuming publication.
    Publishing {
        context: KeyContext,
        prepared: PreparedKeyChange,
        slot: EpochPublicationSlot,
        visibility: ext4_core::VisibilityLease,
    },
    /// No IRP, native exclusion, or unpublished key material remains.
    Terminal,
}

/// One mount-local key operation, joined to the reactor and volume-close mutation drain.
#[derive(Debug)]
pub(super) struct KeyRequestOperation {
    /// Stable ticket retained when a stale snapshot must be resolved again.
    ticket: u64,
    /// Prevents volume close from overtaking an admitted key publication.
    _activity: MutationActivityLease,
    /// Sole owner of the currently permitted protocol step.
    state: KeyState,
}

impl KeyRequestOperation {
    /// Captures native authority and all operation allocation without losing completion ownership.
    /// # Errors
    /// Returns the still-owned IRP on access, native exclusion, crypto, admission, or allocation failure.
    pub(super) fn try_new(
        mut owned: OwnedIrp,
        control: crate::irp::PreparedKeyControl,
        access: &mut MountedVolumeAccess<'_>,
    ) -> Result<Box<dyn CompletionOperation>, AdmitOperationError> {
        let prepared = (|| -> DriverResult<_> {
            crate::request::fsctl::authorize_key_control(&mut owned.request(), access, control)?;
            let request = match control {
                crate::irp::PreparedKeyControl::Add => {
                    KeyRequest::Add(access.new_crypto_operation()?)
                }
                crate::irp::PreparedKeyControl::Remove => {
                    let exclusion = owned.request().with_active(|active| {
                        let opened = crate::state::OpenedVolume::decode(
                            active.current_stack()?.file_object()?,
                        )?;
                        access.begin_key_removal(opened.file_object())
                    })?;
                    KeyRequest::Remove(exclusion)
                }
            };
            let (ticket, activity) = access.admit_key_change()?;
            Ok((request, ticket, activity))
        })();
        let (request, ticket, activity) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => return Err(AdmitOperationError::new(error, owned)),
        };
        match memory::boxed_try_map((owned, request, activity), |(owned, request, activity)| {
            Self {
                ticket,
                _activity: activity,
                state: KeyState::Ready { owned, request },
            }
        }) {
            Ok(operation) => Ok(operation),
            Err(error) => {
                let (error, (owned, _request, _activity)) = error.into_parts();
                Err(AdmitOperationError::new(error, owned))
            }
        }
    }

    /// Re-resolves the latest key snapshot before requesting its whole resource set.
    fn resolve(
        mut self: Box<Self>,
        mut owned: OwnedIrp,
        mut request: KeyRequest,
        access: &MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        let resolution = (|| -> DriverResult<_> {
            let mut lease = owned.request();
            crate::request::fsctl::authorize_key_control(&mut lease, access, request.control())?;
            let stack =
                lease.with_active(|active| active.current_stack()?.file_system_control())?;
            match &mut request {
                KeyRequest::Add(crypto) => crate::request::fsctl::resolve_encryption_key_addition(
                    &mut lease,
                    stack,
                    access,
                    self.ticket,
                    crypto,
                ),
                KeyRequest::Remove(_exclusion) => {
                    crate::request::fsctl::resolve_encryption_key_removal(
                        &mut lease,
                        stack,
                        access,
                        self.ticket,
                    )
                }
            }
        })();
        let (resolved, completion) = match resolution {
            Ok(resolved) => resolved,
            Err(error) => return OperationTransition::Complete(owned.prepare_result(Err(error))),
        };
        let resources = resolved.observed_resources().resources();
        let mut requested = match memory::DriverVec::try_with_capacity(resources.len()) {
            Ok(requested) => requested,
            Err(error) => return OperationTransition::Complete(owned.prepare_result(Err(error))),
        };
        for resource in resources {
            if let Err(error) = requested.try_push(resource) {
                return OperationTransition::Complete(owned.prepare_result(Err(error)));
            }
        }
        self.state = KeyState::Intent {
            context: KeyContext {
                owned,
                request,
                completion,
            },
            resolved,
        };
        OperationTransition::RequestIntent {
            request: IntentRequest::new(self.ticket, requested),
            suspended: self,
        }
    }

    /// Releases all unpublished state through the returned operation's consuming completion.
    fn fail(context: KeyContext, error: DriverError) -> OperationTransition {
        OperationTransition::Complete(context.owned.prepare_result(Err(error)))
    }
}

impl MountedVolumeOperation for KeyRequestOperation {
    fn advance_mounted(
        mut self: Box<Self>,
        event: CompletionEvent,
        access: &mut MountedVolumeAccess<'_>,
    ) -> OperationTransition {
        let state = core::mem::replace(&mut self.state, KeyState::Terminal);
        match (state, event) {
            (
                KeyState::Ready { owned, request },
                CompletionEvent::Core(OperationEvent::Admitted),
            ) => self.resolve(owned, request, access),
            (
                KeyState::Intent { context, resolved },
                CompletionEvent::Core(OperationEvent::IntentGranted(intent)),
            ) => match access.reserve_key_change(resolved, intent) {
                Ok(reserved) => {
                    self.state = KeyState::Commit { context, reserved };
                    OperationTransition::RequestCommit {
                        ticket: self.ticket,
                        suspended: self,
                    }
                }
                Err(DriverError::Core(Error::ClusterReferenceConflict)) => {
                    self.resolve(context.owned, context.request, access)
                }
                Err(error) => Self::fail(context, error),
            },
            (
                KeyState::Commit { context, reserved },
                CompletionEvent::Core(OperationEvent::CommitGranted(commit)),
            ) => {
                let slot = match access.reserve_key_publication() {
                    Ok(slot) => slot,
                    Err(error) => return Self::fail(context, error),
                };
                let prepared = match access.prepare_key_change(reserved, commit) {
                    Ok(prepared) => prepared,
                    Err(error) => return Self::fail(context, error),
                };
                self.state = KeyState::Visibility {
                    context,
                    prepared,
                    slot,
                };
                OperationTransition::Wait {
                    condition: WaitCondition::Visibility {
                        ticket: self.ticket,
                    },
                    suspended: self,
                }
            }
            (
                KeyState::Visibility {
                    context,
                    prepared,
                    slot,
                },
                CompletionEvent::Core(OperationEvent::VisibilityGranted(visibility)),
            ) => {
                self.state = KeyState::Publishing {
                    context,
                    prepared,
                    slot,
                    visibility,
                };
                OperationTransition::Publish { publication: self }
            }
            (
                KeyState::Ready {
                    owned,
                    request: _request,
                },
                CompletionEvent::VolumeFailed(error),
            ) => OperationTransition::Complete(owned.prepare_result(Err(error))),
            (
                KeyState::Intent { context, .. } | KeyState::Commit { context, .. },
                CompletionEvent::VolumeFailed(error),
            ) => Self::fail(context, error),
            (
                KeyState::Visibility {
                    context, prepared, ..
                }
                | KeyState::Publishing {
                    context, prepared, ..
                },
                CompletionEvent::VolumeFailed(error),
            ) => {
                access.abort_key_change(prepared);
                Self::fail(context, error)
            }
            (
                KeyState::Ready {
                    owned,
                    request: _request,
                },
                CompletionEvent::Core(OperationEvent::CancelRequested),
            ) => OperationTransition::Complete(
                owned.prepare_result(Err(DriverError::from(Error::OperationCancelled))),
            ),
            (
                KeyState::Intent { context, .. } | KeyState::Commit { context, .. },
                CompletionEvent::Core(OperationEvent::CancelRequested),
            ) => Self::fail(context, DriverError::from(Error::OperationCancelled)),
            (
                KeyState::Visibility {
                    context, prepared, ..
                }
                | KeyState::Publishing {
                    context, prepared, ..
                },
                CompletionEvent::Core(OperationEvent::CancelRequested),
            ) => {
                access.abort_key_change(prepared);
                Self::fail(context, DriverError::from(Error::OperationCancelled))
            }
            (KeyState::Terminal, CompletionEvent::Core(OperationEvent::Admitted)) => {
                OperationTransition::Retired
            }
            _ => {
                crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                    .bugcheck()
            }
        }
    }

    fn record_mounted_storage_failure(
        &mut self,
        _failure: StorageFailureClass,
        _access: &mut MountedVolumeAccess<'_>,
    ) {
        crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
            .bugcheck();
    }
}

impl InfalliblePublication for KeyRequestOperation {
    fn authority(&self) -> PublicationAuthority {
        PublicationAuthority::Mutation {
            ticket: self.ticket,
        }
    }

    fn publish(
        mut self: Box<Self>,
        access: &mut MountedVolumeAccess<'_>,
    ) -> (
        Box<dyn CompletionOperation>,
        Option<crate::irp::PreparedIrpCompletion>,
    ) {
        let KeyState::Publishing {
            context,
            prepared,
            slot,
            visibility,
        } = core::mem::replace(&mut self.state, KeyState::Terminal)
        else {
            crate::kernel::fatal::KernelWideInconsistency::completion_reactor_state_corruption()
                .bugcheck();
        };
        access.publish_keys(prepared, visibility, slot);
        let KeyContext {
            owned,
            request,
            completion,
        } = context;
        drop(request);
        (self, Some(owned.prepare_completion(completion)))
    }
}

impl_mounted_operation_adapter!(KeyRequestOperation);
