//! Independent ownership, permission and boundary vectors for the shared security contract.
use ext4_core::{Ext4Gid, Ext4Owner, Ext4Permissions, Ext4Security, Ext4Uid, FilesystemUuid};
use ext4_security::*;

/// Constructs one core-valid fixture.
/// # Errors
/// Returns invalid encoding if a fixture mode is invalid.
fn security(mode: u16) -> Result<Ext4Security, Error> {
    Ok(Ext4Security::new(
        Ext4Owner::new(Ext4Uid::from_u32(1000), Ext4Gid::from_u32(100)),
        Ext4Permissions::new(mode).map_err(|_| Error::InvalidEncoding)?,
    ))
}
/// Real-length Windows account SIDs exercise variable descriptor offsets.
/// # Errors
/// Returns validation/allocation failure.
fn map() -> Result<IdentityMap, Error> {
    IdentityMap::new(alloc_users()?, alloc_groups()?)
}
/// Allocates the explicit user fixture.
/// # Errors
/// Returns a SID validation failure.
fn alloc_users() -> Result<Vec<UserMapping>, Error> {
    Ok(vec![UserMapping {
        uid: Ext4Uid::from_u32(1000),
        sid: Sid::parse(&[
            1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0xe8, 3, 0, 0,
        ])?,
    }])
}
/// Allocates the explicit group fixture.
/// # Errors
/// Returns a SID validation failure.
fn alloc_groups() -> Result<Vec<GroupMapping>, Error> {
    Ok(vec![GroupMapping {
        gid: Ext4Gid::from_u32(100),
        sid: Sid::parse(&[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x21, 2, 0, 0])?,
    }])
}
/// Projection is reversible for every mode and component selection, including special bits.
/// # Errors
/// Returns a codec failure.
/// # Panics
/// Panics if an observable ownership/mode contract is violated.
#[expect(
    clippy::panic_in_result_fn,
    reason = "test assertions report contract failures while fixture setup propagates validation errors"
)]
#[test]
fn variable_descriptor_roundtrip() -> Result<(), Error> {
    let map = map()?;
    for mode in 0..=0o7777 {
        for bits in 1..=7 {
            let target = security(mode)?;
            let selection = Components::new(bits)?;
            let descriptor = Descriptor::encode(target, &map, selection)?;
            let actual = Descriptor::decode(descriptor.bytes(), &map, selection, target)?;
            assert_eq!(actual, target);
            assert!(descriptor.bytes().len() <= MAX_DESCRIPTOR_BYTES);
        }
    }
    assert_ne!(
        Descriptor::encode(security(0o640)?, &map, Components::ALL)?
            .bytes()
            .len(),
        Descriptor::encode(security(0o777)?, &IdentityMap::empty(), Components::ALL)?
            .bytes()
            .len()
    );
    Ok(())
}
/// Table records retain identity and generation and reject duplicate authority/truncation.
/// # Errors
/// Returns a fixture construction failure.
/// # Panics
/// Panics if control or identity validation is violated.
#[expect(
    clippy::panic_in_result_fn,
    reason = "test assertions report contract failures while fixture setup propagates validation errors"
)]
#[test]
fn bounded_identity_codec() -> Result<(), Error> {
    let snapshot = MappingSnapshot {
        uuid: FilesystemUuid::from_bytes([3; 16]),
        generation: 7,
        map: map()?,
    };
    let bytes = snapshot.encode()?;
    assert_eq!(MappingSnapshot::decode(&bytes)?, snapshot);
    for length in 0..bytes.len() {
        assert!(
            MappingSnapshot::decode(bytes.get(..length).ok_or(Error::InvalidEncoding)?).is_err()
        );
    }
    let entry = *snapshot.map.users().first().ok_or(Error::InvalidEncoding)?;
    assert_eq!(
        IdentityMap::new(vec![entry, entry], vec![]),
        Err(Error::DuplicateIdentity)
    );
    assert_eq!(
        snapshot
            .map
            .creator(Sid::unix(1, 1000)?, Sid::unix(2, 100)?),
        Err(Error::UnmappedIdentity)
    );
    let replacement = Replacement::new(6, snapshot)?;
    assert_eq!(Replacement::decode(&replacement.encode()?)?, replacement);
    let state = MappingState {
        outcome: PublicationOutcome::SavedNotApplied,
        status: -7,
        saved_generation: 8,
        active: replacement.next,
    };
    assert_eq!(MappingState::decode(&state.encode()?)?, state);
    Ok(())
}
/// Creation uses effective UID and primary GID; setgid changes only inherited GID and directory bit.
/// # Errors
/// Returns a fixture construction failure.
/// # Panics
/// Panics if metadata inheritance differs from the POSIX contract.
#[expect(
    clippy::panic_in_result_fn,
    reason = "test assertions report contract failures while fixture setup propagates validation errors"
)]
#[test]
fn creation_metadata() -> Result<(), Error> {
    let creator = Ext4Owner::new(Ext4Uid::from_u32(2000), Ext4Gid::from_u32(200));
    let parent = security(0o2755)?;
    for (kind, mode) in [(ChildKind::File, 0o644), (ChildKind::Directory, 0o2755)] {
        let child = child_security(creator, parent, kind)?;
        assert_eq!(
            child.owner(),
            Ext4Owner::new(creator.uid(), parent.owner().gid())
        );
        assert_eq!(child.permissions().as_u16(), mode);
    }
    assert_eq!(
        child_security(creator, security(0o755)?, ChildKind::File)?.owner(),
        creator
    );
    Ok(())
}
/// Incomplete permission bundles are not representable as rwx.
/// # Panics
/// Panics if shared rights enter a POSIX bundle or partial bundles are accepted.
#[test]
fn specific_right_contract() {
    assert_eq!(BASE_RIGHTS & CONTROLLED_RIGHTS, 0);
    assert!(rights_mode(1).is_err());
    assert!(rights_mode(WRITE_RIGHTS | 0x100000).is_err());
    assert!(!MAXIMUM_CANDIDATES.contains(&0x80000));
    assert!(!MAXIMUM_CANDIDATES.contains(&0x1000000));
}
