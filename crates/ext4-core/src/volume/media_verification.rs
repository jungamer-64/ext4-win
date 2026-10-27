//! Read-only media verification uses a fresh transcript without mounted cache or epoch overlays.

use super::scope::*;
use crate::disk::storage::{StorageTarget, StorageTranscript};
use alloc::boxed::Box;

/// One-shot verification of the physical primary against a mounted filesystem's fixed identity.
#[derive(Debug)]
pub struct MediaVerificationOperation {
    /// Strictly validated immutable mount interpretation.
    expected: Superblock,
    /// Read/write feature policy established before the original mount.
    access: super::MediaAccess,
    /// Fresh physical reads only; no committed overlay may enter this transcript.
    physical: StorageTranscript,
}

/// Physical metadata interpretation is separate from read completion and media identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MediaVerificationOutcome {
    /// Authenticated primary metadata identifies the mounted filesystem and geometry.
    Same,
    /// A valid primary belongs to another filesystem or immutable layout.
    Different,
    /// Physical bytes cannot establish a valid identity under the mount's format policy.
    Invalid(Error),
}

/// Verification can request only reads and cannot establish recovery or write authority.
#[derive(Debug)]
pub enum MediaVerificationTransition {
    /// Caller submits this raw read with media-verification override semantics.
    SubmitLower {
        /// Owned physical read independent from mounted metadata and data caches.
        request: crate::StorageRequest,
        /// Unique consumer of the read completion.
        suspended: Box<MediaVerificationOperation>,
    },
    /// Physical read failure remains distinct from a different or invalid media identity.
    Complete(Result<MediaVerificationOutcome>),
}

impl MediaVerificationOperation {
    /// Captures immutable interpretation without acquiring cache, mutation or recovery authority.
    pub(super) fn new(
        expected: Superblock,
        access: super::MediaAccess,
        length: DeviceLength,
    ) -> Self {
        Self {
            expected,
            access,
            physical: StorageTranscript::new(StorageTarget::Filesystem, length),
        }
    }

    /// Advances an owned physical observation; malformed media is distinct from a different identity.
    #[must_use]
    pub fn advance(
        mut self: Box<Self>,
        event: super::OperationEvent,
    ) -> MediaVerificationTransition {
        let accepted = match event {
            super::OperationEvent::Admitted => Ok(()),
            super::OperationEvent::StorageCompleted(completion) => {
                self.physical.complete(completion)
            }
            super::OperationEvent::CancelRequested => Err(Error::OperationCancelled),
            _ => Err(Error::DeviceIo),
        };
        if let Err(error) = accepted {
            return MediaVerificationTransition::Complete(Err(error));
        }
        let result = (|| {
            let mut bytes = [0; 1024];
            OperationDevice::new(&mut self.physical)
                .read_exact_at(ByteOffset::new(1024), &mut bytes)?;
            let observed = match self.access {
                super::MediaAccess::ReadWrite => Superblock::parse_read_write(&bytes),
                super::MediaAccess::ReadOnly => Superblock::parse_read_only(&bytes),
            };
            Ok(match observed {
                Ok(observed) if self.expected.same_media_identity(observed) => {
                    MediaVerificationOutcome::Same
                }
                Ok(_) => MediaVerificationOutcome::Different,
                Err(error) => MediaVerificationOutcome::Invalid(error),
            })
        })();
        match result {
            Err(Error::OperationSuspended) => match self.physical.take_pending_request() {
                Ok(request) => MediaVerificationTransition::SubmitLower {
                    request,
                    suspended: self,
                },
                Err(error) => MediaVerificationTransition::Complete(Err(error)),
            },
            result => MediaVerificationTransition::Complete(result),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CompletedStorageTransfer, StorageCompletion, StorageRequest};

    /// Independently assembled unjournaled 1 KiB ext4 geometry for a read-only mount.
    /// # Errors
    /// Returns malformed fixture field encoding.
    fn primary() -> Result<[u8; 1024]> {
        let mut raw = [0; 1024];
        for (offset, value) in [
            (0, 128),
            (4, 4096),
            (20, 1),
            (32, 8192),
            (36, 8192),
            (40, 128),
            (76, 1),
            (84, 11),
            (96, 0x42),
        ] {
            put_le_u32(&mut raw, DiskOffset::new(offset), value)?;
        }
        put_le_u16(&mut raw, DiskOffset::new(56), 0xef53)?;
        put_le_u16(&mut raw, DiskOffset::new(58), 1)?;
        put_le_u16(&mut raw, DiskOffset::new(88), 256)?;
        Ok(raw)
    }

    /// # Errors
    /// Returns fixture construction or raw-completion framing failure.
    /// # Panics
    /// Fails if verification uses an overlay, omits a physical primary read, or compares mutable accounting.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "independent physical vectors observe raw read coordinates and mounted-identity outcomes"
    )]
    fn physical_primary_identity_is_independent_from_mutable_mount_metadata() -> Result<()> {
        let raw = primary()?;
        let expected = Superblock::parse_read_only(&raw)?;
        for (field, value, outcome) in [
            (12, 10, MediaVerificationOutcome::Same),
            (4, 8192, MediaVerificationOutcome::Different),
            (104, 42, MediaVerificationOutcome::Different),
        ] {
            let mut observed = raw;
            put_le_u32(&mut observed, DiskOffset::new(field), value)?;
            let probe = memory::try_box(MediaVerificationOperation::new(
                expected,
                super::super::MediaAccess::ReadOnly,
                DeviceLength::from_bytes(4_194_304),
            ))?;
            let MediaVerificationTransition::SubmitLower {
                mut request,
                suspended,
            } = probe.advance(super::super::OperationEvent::Admitted)
            else {
                return Err(Error::DeviceIo);
            };
            let StorageRequest::Read {
                target,
                offset,
                buffer,
            } = &mut request
            else {
                return Err(Error::DeviceIo);
            };
            assert_eq!(*target, StorageTarget::Filesystem);
            assert_eq!(*offset, ByteOffset::new(1024));
            assert_eq!(buffer.len(), 1024);
            memory::copy_exact(buffer, &observed)?;
            let completion =
                StorageCompletion::success(CompletedStorageTransfer::from_request(request), 1024);
            assert!(
                matches!(suspended.advance(super::super::OperationEvent::StorageCompleted(completion)), MediaVerificationTransition::Complete(Ok(actual)) if actual == outcome)
            );
        }
        let probe = memory::try_box(MediaVerificationOperation::new(
            expected,
            super::super::MediaAccess::ReadOnly,
            DeviceLength::from_bytes(4_194_304),
        ))?;
        let MediaVerificationTransition::SubmitLower { request, suspended } =
            probe.advance(super::super::OperationEvent::Admitted)
        else {
            return Err(Error::DeviceIo);
        };
        let completion = StorageCompletion::failure(
            CompletedStorageTransfer::from_request(request),
            Error::DeviceIo,
        );
        assert!(matches!(
            suspended.advance(super::super::OperationEvent::StorageCompleted(completion)),
            MediaVerificationTransition::Complete(Err(Error::DeviceIo))
        ));
        Ok(())
    }
}
