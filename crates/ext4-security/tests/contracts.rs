//! Independent ownership, permission and boundary vectors for the shared security contract.
#[cfg(windows)]
use ext4_core::Ext4Access;
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
#[cfg(windows)]
fn variable_descriptor_roundtrip() -> Result<(), Error> {
    let map = map()?;
    for mode in 0..=0o7777 {
        for bits in 1..=7 {
            let target = security(mode)?;
            let selection = Components::new(bits)?;
            let descriptor = Descriptor::encode(&Ext4Access::from_mode(target), &map, selection)?;
            let actual = Descriptor::decode(
                descriptor.bytes(),
                &map,
                selection,
                &Ext4Access::from_mode(target),
            )?;
            assert_eq!(actual, target);
            assert!(descriptor.bytes().len() <= MAX_DESCRIPTOR_BYTES);
        }
    }
    assert_ne!(
        Descriptor::encode(
            &Ext4Access::from_mode(security(0o640)?),
            &map,
            Components::ALL
        )?
        .bytes()
        .len(),
        Descriptor::encode(
            &Ext4Access::from_mode(security(0o777)?),
            &IdentityMap::empty(),
            Components::ALL
        )?
        .bytes()
        .len()
    );
    Ok(())
}

/// Maximum-length owner/group SIDs occupy the complete descriptor budget.
/// # Errors
/// Returns fixture SID, identity or descriptor construction failure.
/// # Panics
/// Panics if a valid maximum-size descriptor cannot be encoded within its declared bound.
#[expect(
    clippy::panic_in_result_fn,
    reason = "fixture failures propagate while the observable descriptor bound uses assertions"
)]
#[test]
#[cfg(windows)]
fn maximum_sid_descriptor_fits_the_reserved_budget() -> Result<(), Error> {
    let map = IdentityMap::new(
        vec![UserMapping {
            uid: Ext4Uid::from_u32(1000),
            sid: "S-1-5-21-1-2-3-4-5-6-7-8-9-10-11-12-13-14".parse()?,
        }],
        vec![GroupMapping {
            gid: Ext4Gid::from_u32(100),
            sid: "S-1-5-21-1-2-3-4-5-6-7-8-9-10-11-12-13-15".parse()?,
        }],
    )?;
    let target = security(0)?;
    let descriptor = Descriptor::encode(&Ext4Access::from_mode(target), &map, Components::ALL)?;
    assert_eq!(descriptor.bytes().len(), 488);
    assert!(descriptor.bytes().len() <= MAX_DESCRIPTOR_BYTES);
    assert_eq!(
        Descriptor::decode(
            descriptor.bytes(),
            &map,
            Components::ALL,
            &Ext4Access::from_mode(target)
        )?,
        target
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
    assert_eq!(
        bytes,
        [
            b'E', b'4', b'I', b'M', 1, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 3, 3, 3, 3, 3, 3, 3, 3, 3,
            3, 3, 3, 3, 3, 3, 3, 1, 0, 0, 0, 1, 0, 0, 0, 0xe8, 3, 0, 0, 28, 0, 0, 0, 1, 5, 0, 0, 0,
            0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0xe8, 3, 0, 0, 100, 0, 0, 0,
            16, 0, 0, 0, 1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x21, 2, 0, 0,
        ]
    );
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
        active: replacement.into_next(),
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

/// Text vectors preserve the on-disk UUID byte order and full SID authority width.
/// # Errors
/// Returns codec failure.
/// # Panics
/// Panics if the independent text vectors are changed.
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions report contract failures after fallible setup"
)]
#[test]
fn identity_text_vectors() -> Result<(), Error> {
    let uuid = parse_uuid("00112233-4455-6677-8899-aabbccddeeff")?;
    assert_eq!(
        uuid.bytes(),
        [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff
        ]
    );
    assert_eq!(&uuid_text(uuid), b"00112233-4455-6677-8899-aabbccddeeff");
    let text = "S-1-281474976710655-0-4294967295";
    let sid: Sid = text.parse()?;
    assert_eq!(
        sid.bytes(),
        &[
            1, 2, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255
        ]
    );
    assert_eq!(sid.to_string(), text);
    assert!("S-1-281474976710656-0".parse::<Sid>().is_err());
    Ok(())
}

/// # Errors
/// Returns SID construction failure.
/// # Panics
/// Panics if a mapping aliases a synthetic presentation identity.
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions verify bijection while fallible SID setup propagates"
)]
#[test]
fn synthetic_identity_remains_bijective() -> Result<(), Error> {
    assert_eq!(
        IdentityMap::new(
            vec![UserMapping {
                sid: Sid::unix(1, 2000)?,
                uid: Ext4Uid::from_u32(1000)
            }],
            vec![]
        ),
        Err(Error::DuplicateIdentity)
    );
    let map = map()?;
    assert_eq!(map.uid(Sid::unix(1, 1000)?), Err(Error::UnmappedIdentity));
    #[cfg(windows)]
    {
        let unmapped = Ext4Owner::new(Ext4Uid::from_u32(2000), Ext4Gid::from_u32(200));
        let security = Ext4Security::new(
            unmapped,
            Ext4Permissions::new(0o640).map_err(|_| Error::InvalidEncoding)?,
        );
        let descriptor =
            Descriptor::encode(&Ext4Access::from_mode(security), &map, Components::ALL)?;
        assert_eq!(
            Descriptor::decode(
                descriptor.bytes(),
                &map,
                Components::ALL,
                &Ext4Access::from_mode(security)
            )?,
            security
        );
    }
    Ok(())
}

/// # Errors
/// Returns ACL or descriptor fixture failure.
/// # Panics
/// Panics if descriptor roundtrip erases a named entry or a changed ACL is accepted as mode.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions compare the validated ACL with independent descriptor mutations"
)]
#[cfg(windows)]
fn extended_acl_descriptor_preserves_policy() -> Result<(), Error> {
    let acl = ext4_core::PosixAcl::parse(&[
        1, 0, 0, 0, 1, 0, 6, 0, 2, 0, 6, 0, 233, 3, 0, 0, 4, 0, 6, 0, 16, 0, 4, 0, 32, 0, 0, 0,
    ])
    .map_err(|_| Error::InvalidEncoding)?;
    let access =
        Ext4Access::new(security(0o640)?, Some(acl)).map_err(|_| Error::InvalidEncoding)?;
    let map = map()?;
    let descriptor = Descriptor::encode(&access, &map, Components::ALL)?;
    assert_eq!(
        Descriptor::decode(descriptor.bytes(), &map, Components::ALL, &access)?,
        access.security()
    );
    let mut changed = descriptor.bytes().to_vec();
    let offset = u32::from_le_bytes(
        changed
            .get(16..20)
            .ok_or(Error::InvalidEncoding)?
            .try_into()
            .map_err(|_| Error::InvalidEncoding)?,
    );
    let mask = usize::try_from(offset)
        .map_err(|_| Error::InvalidEncoding)?
        .checked_add(12)
        .ok_or(Error::InvalidEncoding)?;
    *changed.get_mut(mask).ok_or(Error::InvalidEncoding)? ^= 1;
    assert_eq!(
        Descriptor::decode(&changed, &map, Components::ALL, &access),
        Err(Error::UnrepresentableDescriptor)
    );
    Ok(())
}

/// # Errors
/// Returns ACL construction or identity failure.
/// # Panics
/// Panics if the native ACL length budget silently truncates a valid POSIX policy.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions verify the native ACL's independent sixteen-bit size limit"
)]
#[cfg(windows)]
fn descriptor_reports_native_acl_size_exhaustion() -> Result<(), Error> {
    let mut bytes = vec![1, 0, 0, 0, 1, 0, 6, 0];
    for id in 1_u32..=2000 {
        bytes.extend_from_slice(&[2, 0, 4, 0]);
        bytes.extend_from_slice(&id.to_le_bytes());
    }
    bytes.extend_from_slice(&[4, 0, 4, 0, 16, 0, 4, 0, 32, 0, 0, 0]);
    let acl = ext4_core::PosixAcl::parse(&bytes).map_err(|_| Error::InvalidEncoding)?;
    let access =
        Ext4Access::new(security(0o640)?, Some(acl)).map_err(|_| Error::InvalidEncoding)?;
    assert!(matches!(
        Descriptor::encode(&access, &IdentityMap::empty(), Components::ALL),
        Err(Error::RecordTooLarge)
    ));
    Ok(())
}
