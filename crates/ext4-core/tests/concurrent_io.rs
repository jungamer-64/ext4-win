//! Concurrent read and mutation contracts over independently generated ext4 journal fixtures.

#![feature(allocator_api)]

extern crate alloc;

use alloc::{boxed::Box, vec::Vec};
use ext4_core::*;

/// Plain fixtures must never request cryptographic execution.
#[derive(Debug)]
struct PlainCrypto;

impl CryptographicOperation for PlainCrypto {
    fn fill_random(&mut self, _: &mut [u8]) -> Result<()> {
        Err(Error::CryptographicFailure)
    }
    fn hkdf_sha512(&mut self, _: &[u8], _: &[u8], _: &mut [u8]) -> Result<()> {
        Err(Error::CryptographicFailure)
    }
    fn encrypt_aes_256_xts(&mut self, _: &[u8; 64], _: u64, _: &mut [u8]) -> Result<()> {
        Err(Error::CryptographicFailure)
    }
    fn decrypt_aes_256_xts(&mut self, _: &[u8; 64], _: u64, _: &mut [u8]) -> Result<()> {
        Err(Error::CryptographicFailure)
    }
    fn encrypt_aes_256_cbc_cs3(&mut self, _: &[u8; 32], _: &mut [u8]) -> Result<()> {
        Err(Error::CryptographicFailure)
    }
    fn decrypt_aes_256_cbc_cs3(&mut self, _: &[u8; 32], _: &mut [u8]) -> Result<()> {
        Err(Error::CryptographicFailure)
    }
    fn sha256(&mut self, _: &[u8]) -> Result<[u8; 32]> {
        Err(Error::CryptographicFailure)
    }
    fn sha512(&mut self, _: &[u8]) -> Result<[u8; 64]> {
        Err(Error::CryptographicFailure)
    }
}

/// Only these private in-memory copies are mutated; tracked fixture images remain inputs.
#[derive(Debug)]
struct Disk {
    filesystem: Vec<u8>,
    journal: Vec<u8>,
}

impl Disk {
    fn fixture() -> Self {
        Self {
            filesystem: include_bytes!(
                "../../../tools/xtask/fixtures/journal/external-4k-v3-64.filesystem.img"
            )
            .to_vec(),
            journal: include_bytes!(
                "../../../tools/xtask/fixtures/journal/external-4k-v3-64.journal.img"
            )
            .to_vec(),
        }
    }

    /// # Errors
    /// Returns an invalid device range before copying a malformed transfer.
    fn complete(&mut self, mut request: StorageRequest) -> Result<StorageCompletion> {
        let image = match request.target() {
            StorageTarget::Filesystem => &mut self.filesystem,
            StorageTarget::ExternalJournal => &mut self.journal,
        };
        match &mut request {
            StorageRequest::Read { offset, buffer, .. }
            | StorageRequest::Write { offset, buffer, .. } => {
                let start = usize::try_from(offset.get()).map_err(|_| Error::DeviceRange)?;
                let end = start.checked_add(buffer.len()).ok_or(Error::DeviceRange)?;
                let range = image.get_mut(start..end).ok_or(Error::DeviceRange)?;
                #[expect(
                    clippy::disallowed_methods,
                    reason = "the checked image range is constructed with the exact request buffer length before either copy"
                )]
                match &mut request {
                    StorageRequest::Read { buffer, .. } => buffer.copy_from_slice(range),
                    StorageRequest::Write { buffer, .. } => range.copy_from_slice(buffer),
                    StorageRequest::Flush { .. } => return Err(Error::DeviceIo),
                }
            }
            StorageRequest::Flush { .. } => {}
        }
        let length = request.byte_count();
        Ok(StorageCompletion::success(
            CompletedStorageTransfer::from_request(request),
            length,
        ))
    }

    /// # Errors
    /// Returns a mount, external-journal discovery, or storage failure.
    fn mount(&mut self) -> Result<CompletedMount> {
        let length = u64::try_from(self.filesystem.len()).map_err(|_| Error::DeviceRange)?;
        let mut step = Box::try_new(MountOperation::new(
            DeviceLength::from_bytes(length),
            FscryptKeySet::empty(),
        ))
        .map_err(|_| Error::OutOfMemory)?
        .advance(OperationEvent::Admitted);
        loop {
            step = match step {
                MountTransition::SubmitLower { request, suspended } => {
                    suspended.advance(OperationEvent::StorageCompleted(self.complete(request)?))
                }
                MountTransition::Complete(result) => return result.map(|mounted| *mounted),
                MountTransition::DiscoverExternalJournal {
                    requirement,
                    suspended,
                } => {
                    let length =
                        u64::try_from(self.journal.len()).map_err(|_| Error::DeviceRange)?;
                    let mut probe = Box::try_new(ExternalJournalProbeOperation::new(
                        requirement,
                        DeviceLength::from_bytes(length),
                    ))
                    .map_err(|_| Error::OutOfMemory)?
                    .advance(OperationEvent::Admitted);
                    let journal = loop {
                        probe = match probe {
                            ExternalJournalProbeTransition::SubmitLower { request, suspended } => {
                                suspended.advance(OperationEvent::StorageCompleted(
                                    self.complete(request)?,
                                ))
                            }
                            ExternalJournalProbeTransition::Complete(result) => match result? {
                                ExternalJournalProbeOutcome::Match(journal) => break journal,
                                ExternalJournalProbeOutcome::Mismatch => {
                                    return Err(Error::UnsupportedJournal);
                                }
                            },
                        };
                    };
                    suspended.attach_external_journal(journal)
                }
            };
        }
    }

    /// # Errors
    /// Returns a transfer validation failure without hiding I/O progress.
    fn checked(&mut self, request: StorageRequest) -> Result<()> {
        StorageRequestIdentity::from_request(&request).complete(self.complete(request)?)
    }

    /// # Errors
    /// Returns the first failed transfer in the production sequence.
    fn sequence<N>(&mut self, mut sequence: StorageRequestSequence<N>) -> Result<N> {
        loop {
            match sequence.advance() {
                StorageRequestSequenceStep::Submit { request, suspended } => {
                    self.checked(request)?;
                    sequence = suspended;
                }
                StorageRequestSequenceStep::Finished(next) => return Ok(next),
            }
        }
    }

    /// # Errors
    /// Returns any commit/checkpoint failure; these tests never retry a partially effected commit.
    fn commit(
        &mut self,
        coordinator: &mut MutationCoordinatorState,
        cache: &mut MetadataCache,
        ticket: u64,
        prepared: CommitReadyMutation,
    ) -> Result<CommittedEpoch> {
        let ordered = self.sequence(prepared.start())?;
        self.checked(ordered.flush_request())?;
        let payload = self.sequence(ordered.completed())?;
        self.checked(payload.flush_request())?;
        let (request, durable) = payload.completed().submit();
        self.checked(request)?;
        self.checked(durable.flush_request())?;
        let (epoch, checkpoint) = durable
            .completed()
            .publish(coordinator, VisibilityLease::granted(ticket))
            .into_parts();
        cache.publish(&epoch);
        let home = self.sequence(checkpoint.start(CheckpointLease::granted(epoch.sequence())))?;
        self.checked(home.flush_request())?;
        let (request, clean) = home.completed().submit();
        self.checked(request)?;
        self.checked(clean.flush_request())?;
        let epoch = clean.completed(coordinator);
        cache.publish(&epoch);
        Ok(epoch)
    }

    /// # Errors
    /// Returns read/resolve failure before constructing a mutation with matching epoch versions.
    fn resolve<F, R>(
        &mut self,
        profile: &MountedProfile,
        epoch: &CommittedEpoch,
        coordinator: &MutationCoordinatorState,
        ticket: u64,
        mut mutate: F,
    ) -> Result<(ResolvedMutation, R)>
    where
        F: for<'storage, 'epoch, 'crypto> FnMut(
            &mut MutationResolvePass<'storage, 'epoch, 'crypto>,
        ) -> Result<R>,
    {
        let mut operation = MutationResolveOperation::new(profile);
        let mut event = OperationEvent::Admitted;
        let mut cache = MetadataCache::default();
        loop {
            let mut ready = operation.accept(event)?;
            let mut output = None;
            let mut crypto = PlainCrypto;
            let result = {
                let mut pass = ready.begin_pass(
                    cache.access(epoch),
                    Ext4Timestamp::from_unix_seconds(2),
                    &mut crypto,
                );
                mutate(&mut pass).and_then(|value| {
                    output = Some(value);
                    pass.resolve(ticket, coordinator)
                })
            };
            match ready.finish(result) {
                MutationResolveTransition::SubmitLower { request, suspended } => {
                    event = OperationEvent::StorageCompleted(self.complete(request)?);
                    operation = suspended;
                }
                MutationResolveTransition::Complete(result) => {
                    return Ok((result?, output.ok_or(Error::DeviceIo)?));
                }
            }
        }
    }
}

/// One mount owns current publication, coordinator, and storage independently.
#[derive(Debug)]
struct Fixture {
    disk: Disk,
    profile: MountedProfile,
    epoch: CommittedEpoch,
    coordinator: MutationCoordinatorState,
    cache: MetadataCache,
    a: FileNodeId,
    b: FileNodeId,
}

impl Fixture {
    /// # Errors
    /// Returns fixture mount, allocation, create, write, or commit failure.
    fn new() -> Result<Self> {
        let mut disk = Disk::fixture();
        let (profile, epoch, mut coordinator) = disk.mount()?.into_parts();
        let ticket = coordinator.admit_mutation()?;
        let (resolved, (a, b)) = disk.resolve(&profile, &epoch, &coordinator, ticket, |pass| {
            let root = pass.directory(DirectoryNodeId::ROOT)?;
            let metadata = NewFileMetadata::new(
                Ext4Owner::new(Ext4Uid::from_u32(1000), Ext4Gid::from_u32(1000)),
                Ext4Permissions::new(0o644)?,
            );
            let a = pass.create_file(root, &Ext4Name::new(b"concurrent-a")?, metadata)?;
            let b = pass.create_file(root, &Ext4Name::new(b"concurrent-b")?, metadata)?;
            pass.write_file_range(a, FileOffset::ZERO, b"a")?;
            pass.write_file_range(b, FileOffset::ZERO, b"b")?;
            Ok((a.id(), b.id()))
        })?;
        let mut cache = MetadataCache::try_new(&epoch)?;
        let ready = resolved
            .reserve(&coordinator, MutationLease::granted(ticket))?
            .prepare_commit(
                &mut coordinator,
                &epoch,
                &mut cache,
                CommitLease::granted(ticket),
            )?;
        let epoch = disk.commit(&mut coordinator, &mut cache, ticket, ready)?;
        Ok(Self {
            disk,
            profile,
            epoch,
            coordinator,
            cache,
            a,
            b,
        })
    }

    /// # Errors
    /// Returns a pre-write mutation failure or a commit failure without automatically retrying it.
    fn mutate<F, R>(&mut self, mutate: F) -> Result<R>
    where
        F: for<'storage, 'epoch, 'crypto> FnMut(
            &mut MutationResolvePass<'storage, 'epoch, 'crypto>,
        ) -> Result<R>,
    {
        let ticket = self.coordinator.admit_mutation()?;
        let (resolved, output) = self.disk.resolve(
            &self.profile,
            &self.epoch,
            &self.coordinator,
            ticket,
            mutate,
        )?;
        let ready = resolved
            .reserve(&self.coordinator, MutationLease::granted(ticket))?
            .prepare_commit(
                &mut self.coordinator,
                &self.epoch,
                &mut self.cache,
                CommitLease::granted(ticket),
            )?;
        self.epoch = self
            .disk
            .commit(&mut self.coordinator, &mut self.cache, ticket, ready)?;
        Ok(output)
    }

    /// # Errors
    /// Returns read failure or unexpected completion before the fixture's one-byte payload I/O.
    fn suspend_payload(
        &mut self,
        file: FileNodeId,
        output: &mut [u8; 1],
    ) -> Result<(EpochReadOperation, StorageRequest)> {
        let mut read = EpochReadOperation::new(&self.profile);
        let mut event = OperationEvent::Admitted;
        loop {
            match read.run(
                event,
                self.coordinator
                    .read_context(self.cache.access(&self.epoch))?,
                &mut PlainCrypto,
                |pass| pass.read_file(file, FileOffset::ZERO, output),
            ) {
                ReadTransition::SubmitLower { request, suspended } if request.byte_count() == 1 => {
                    return Ok((suspended, request));
                }
                ReadTransition::SubmitLower { request, suspended } => {
                    event = OperationEvent::StorageCompleted(self.disk.complete(request)?);
                    read = suspended;
                }
                ReadTransition::Complete(result) => {
                    result?;
                    return Err(Error::DeviceIo);
                }
            }
        }
    }
}

/// # Errors
/// Returns a fixture, resolve, or commit failure.
/// # Panics
/// Fails when a neighboring inode update erases a previously committed file size.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "fallible setup is separate from concurrent publication assertions"
)]
fn shared_metadata_images_revalidate_before_overwriting_neighbors() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let a = fixture.a;
    let b = fixture.b;
    let ticket_a = fixture.coordinator.admit_mutation()?;
    let ticket_b = fixture.coordinator.admit_mutation()?;
    let (a_update, ()) = fixture.disk.resolve(
        &fixture.profile,
        &fixture.epoch,
        &fixture.coordinator,
        ticket_a,
        |pass| {
            let file = pass.file(a)?;
            pass.write_file_range(file, FileOffset::from_bytes(1), b"AAA")
        },
    )?;
    let (b_update, ()) = fixture.disk.resolve(
        &fixture.profile,
        &fixture.epoch,
        &fixture.coordinator,
        ticket_b,
        |pass| {
            let file = pass.file(b)?;
            pass.write_file_range(file, FileOffset::from_bytes(1), b"BBB")
        },
    )?;
    let a_resources = a_update
        .observed_resources()
        .resources()
        .collect::<Vec<_>>();
    assert!(
        b_update
            .observed_resources()
            .resources()
            .any(|resource| a_resources.contains(&resource))
    );
    let ready = a_update
        .reserve(&fixture.coordinator, MutationLease::granted(ticket_a))?
        .prepare_commit(
            &mut fixture.coordinator,
            &fixture.epoch,
            &mut fixture.cache,
            CommitLease::granted(ticket_a),
        )?;
    fixture.epoch = fixture.disk.commit(
        &mut fixture.coordinator,
        &mut fixture.cache,
        ticket_a,
        ready,
    )?;
    assert!(matches!(
        b_update.reserve(&fixture.coordinator, MutationLease::granted(ticket_b)),
        Err(Error::ClusterReferenceConflict)
    ));
    fixture.mutate(|pass| {
        let file = pass.file(b)?;
        pass.write_file_range(file, FileOffset::from_bytes(1), b"BBB")
    })?;
    let mut operation = EpochReadOperation::new(&fixture.profile);
    let mut event = OperationEvent::Admitted;
    let mut a_bytes = [0_u8; 4];
    let mut b_bytes = [0_u8; 4];
    loop {
        match operation.run(
            event,
            fixture
                .coordinator
                .read_context(fixture.cache.access(&fixture.epoch))?,
            &mut PlainCrypto,
            |pass| {
                pass.read_file(a, FileOffset::ZERO, &mut a_bytes)?;
                pass.read_file(b, FileOffset::ZERO, &mut b_bytes)?;
                Ok((pass.load_file(a)?.size(), pass.load_file(b)?.size()))
            },
        ) {
            ReadTransition::SubmitLower { request, suspended } => {
                event = OperationEvent::StorageCompleted(fixture.disk.complete(request)?);
                operation = suspended;
            }
            ReadTransition::Complete(result) => {
                assert_eq!(result?, (FileSize::from_bytes(4), FileSize::from_bytes(4)));
                assert_eq!(a_bytes, *b"aAAA");
                assert_eq!(b_bytes, *b"bBBB");
                return Ok(());
            }
        }
    }
}

/// # Errors
/// Returns fixture or mutation failure.
/// # Panics
/// Fails when a suspended reader interprets bytes after its inode releases their physical block.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "fixture mutation is separate from read isolation assertions"
)]
fn block_reuse_revokes_the_suspended_read_before_copying_data() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let mut output = [0_u8; 1];
    let a = fixture.a;
    let (read, request) = fixture.suspend_payload(a, &mut output)?;
    fixture.mutate(|pass| {
        let file = pass.file(a)?;
        pass.truncate_file(file, FileSize::from_bytes(0))
    })?;
    fixture.mutate(|pass| {
        let root = pass.directory(DirectoryNodeId::ROOT)?;
        let metadata = NewFileMetadata::new(
            Ext4Owner::new(Ext4Uid::from_u32(2000), Ext4Gid::from_u32(2000)),
            Ext4Permissions::new(0o600)?,
        );
        let file = pass.create_file(root, &Ext4Name::new(b"concurrent-c")?, metadata)?;
        pass.write_file_range(file, FileOffset::ZERO, b"C")
    })?;
    let completion = fixture.disk.complete(request)?;
    match read.run(
        OperationEvent::StorageCompleted(completion),
        fixture
            .coordinator
            .read_context(fixture.cache.access(&fixture.epoch))?,
        &mut PlainCrypto,
        |pass| pass.read_file(a, FileOffset::ZERO, &mut output),
    ) {
        ReadTransition::Complete(result) => assert_eq!(result, Err(Error::ReadConflict)),
        ReadTransition::SubmitLower { .. } => return Err(Error::DeviceIo),
    }
    assert_eq!(output, [0]);
    Ok(())
}

/// # Errors
/// Returns fixture or mutation failure.
/// # Panics
/// Fails when publication on another inode invalidates an otherwise unchanged payload read.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "fixture mutation is separate from disjoint read progress assertions"
)]
fn unrelated_inode_publication_preserves_the_pending_payload_read() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let a = fixture.a;
    let b = fixture.b;
    let mut output = [0_u8; 1];
    let (read, request) = fixture.suspend_payload(a, &mut output)?;
    fixture.mutate(|pass| {
        let file = pass.file(b)?;
        pass.write_file_range(file, FileOffset::ZERO, b"B")
    })?;
    let completion = fixture.disk.complete(request)?;
    match read.run(
        OperationEvent::StorageCompleted(completion),
        fixture
            .coordinator
            .read_context(fixture.cache.access(&fixture.epoch))?,
        &mut PlainCrypto,
        |pass| pass.read_file(a, FileOffset::ZERO, &mut output),
    ) {
        ReadTransition::Complete(result) => assert_eq!(result?.as_usize(), 1),
        ReadTransition::SubmitLower { .. } => return Err(Error::DeviceIo),
    }
    assert_eq!(output, [b'a']);
    Ok(())
}

/// # Errors
/// Returns fixture, mutation, or read failure.
/// # Panics
/// Fails when a retained whole metadata block supplies a newly observed neighbor's old record.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "fixture storage and cache admission are separate from metadata freshness assertions"
)]
fn cache_replacement_keeps_new_inode_observations_current() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let a = fixture.a;
    let b = fixture.b;
    fixture.cache = MetadataCache::try_new(&fixture.epoch)?;
    let mut output = [0_u8; 1];
    let (mut read, request) = fixture.suspend_payload(a, &mut output)?;
    fixture.mutate(|pass| {
        let file = pass.file(b)?;
        pass.write_file_range(file, FileOffset::from_bytes(1), b"BBB")
    })?;
    fixture.cache = MetadataCache::try_new(&fixture.epoch)?;
    let mut event = OperationEvent::StorageCompleted(fixture.disk.complete(request)?);
    loop {
        match read.run(
            event,
            fixture
                .coordinator
                .read_context(fixture.cache.access(&fixture.epoch))?,
            &mut PlainCrypto,
            |pass| {
                pass.read_file(a, FileOffset::ZERO, &mut output)?;
                Ok(pass.load_file(b)?.size())
            },
        ) {
            ReadTransition::SubmitLower { request, suspended } => {
                event = OperationEvent::StorageCompleted(fixture.disk.complete(request)?);
                read = suspended;
            }
            ReadTransition::Complete(result) => {
                assert_eq!(result?, FileSize::from_bytes(4));
                assert_eq!(output, [b'a']);
                return Ok(());
            }
        }
    }
}

/// # Errors
/// Returns fixture, traversal, or mutation failure.
/// # Panics
/// Fails when entry metadata loses the inode version established by directory traversal.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "fixture traversal is separate from entry projection consistency assertions"
)]
fn directory_entry_projection_retains_its_inode_dependency() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let mut walk = DirectoryReadOperation::new(
        &fixture.profile,
        DirectoryNodeId::ROOT,
        DirectoryScanCursor::start(),
    );
    let mut event = OperationEvent::Admitted;
    let node = NodeId::File(fixture.a);
    let read = loop {
        match walk.advance(
            event,
            fixture
                .coordinator
                .read_context(fixture.cache.access(&fixture.epoch))?,
            &mut PlainCrypto,
        ) {
            DirectoryReadTransition::SubmitLower { request, suspended } => {
                event = OperationEvent::StorageCompleted(fixture.disk.complete(request)?);
                walk = suspended;
            }
            DirectoryReadTransition::Entry {
                entry,
                continuation,
            } => {
                if *entry.entry().node() == node {
                    break continuation.entry_read(&fixture.profile, node)?;
                }
                event = OperationEvent::Admitted;
                walk = continuation;
            }
            DirectoryReadTransition::Complete(result) => {
                result?;
                return Err(Error::DirectoryEntryNotFound);
            }
        }
    };
    let a = fixture.a;
    fixture.mutate(|pass| {
        let file = pass.file(a)?;
        pass.truncate_file(file, FileSize::from_bytes(0))
    })?;
    match read.run(
        OperationEvent::Admitted,
        fixture
            .coordinator
            .read_context(fixture.cache.access(&fixture.epoch))?,
        &mut PlainCrypto,
        |pass| pass.load_node_metadata(node),
    ) {
        ReadTransition::Complete(result) => assert_eq!(result, Err(Error::ReadConflict)),
        ReadTransition::SubmitLower { .. } => return Err(Error::DeviceIo),
    }
    Ok(())
}

/// # Errors
/// Returns fixture, resolve, or commit failure.
/// # Panics
/// Fails when metadata from an earlier publication is paired with current resource versions.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "fixture commit is separate from current-context admission assertions"
)]
fn current_versions_reject_an_earlier_epoch_at_admission() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let a = fixture.a;
    let ticket = fixture.coordinator.admit_mutation()?;
    let (resolved, ()) = fixture.disk.resolve(
        &fixture.profile,
        &fixture.epoch,
        &fixture.coordinator,
        ticket,
        |pass| {
            let file = pass.file(a)?;
            pass.write_file_range(file, FileOffset::ZERO, b"A")
        },
    )?;
    let ready = resolved
        .reserve(&fixture.coordinator, MutationLease::granted(ticket))?
        .prepare_commit(
            &mut fixture.coordinator,
            &fixture.epoch,
            &mut fixture.cache,
            CommitLease::granted(ticket),
        )?;
    let current =
        fixture
            .disk
            .commit(&mut fixture.coordinator, &mut fixture.cache, ticket, ready)?;
    assert!(matches!(
        fixture
            .coordinator
            .read_context(fixture.cache.access(&fixture.epoch)),
        Err(Error::StaleReadContext)
    ));
    let ticket = fixture.coordinator.admit_mutation()?;
    assert!(matches!(
        fixture.disk.resolve(
            &fixture.profile,
            &fixture.epoch,
            &fixture.coordinator,
            ticket,
            |pass| {
                let file = pass.file(a)?;
                pass.write_file_range(file, FileOffset::ZERO, b"a")
            }
        ),
        Err(Error::ClusterReferenceConflict)
    ));
    fixture.epoch = current;
    Ok(())
}
