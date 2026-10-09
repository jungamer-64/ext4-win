//! Windows Security Reference Monitor oracle using real, deny-only and restricted tokens.
use super::*;
use ext4_core::{Ext4Gid, Ext4Owner, Ext4Permissions, Ext4Security, Ext4Uid};
use ext4_security::{
    AccessDecision, Components, Descriptor, GroupMapping, IdentityMap, MAXIMUM_ALLOWED,
    UserMapping, WRITE_RIGHTS, evaluate_access,
};
use windows_sys::Win32::System::Threading::SetThreadToken;

/// Opens a process token with explicit duplication authority for the oracle.
/// # Errors
/// Returns native token admission failure.
fn process_token() -> io::Result<OwnedHandle> {
    let process = unsafe {
        // SAFETY: The current-process pseudo handle is borrowed and never closed.
        GetCurrentProcess()
    };
    let mut token = ptr::null_mut();
    let success = unsafe {
        // SAFETY: Output is initialized writable handle storage.
        OpenProcessToken(process, TOKEN_QUERY | TOKEN_DUPLICATE, &mut token)
    };
    if success == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe {
        // SAFETY: Success transfers one uniquely owned native token handle.
        OwnedHandle::from_raw_handle(token)
    })
}
/// Produces the impersonation-token form required by AccessCheck.
/// # Errors
/// Returns a native duplication failure.
fn impersonation(token: &OwnedHandle) -> io::Result<OwnedHandle> {
    let mut result = ptr::null_mut();
    let success = unsafe {
        // SAFETY: Input is retained; output receives a distinct owned token.
        DuplicateTokenEx(
            token.as_raw_handle(),
            TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_ADJUST_PRIVILEGES,
            ptr::null(),
            SecurityImpersonation,
            TokenImpersonation,
            &mut result,
        )
    };
    if success == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe {
        // SAFETY: Successful duplication transfers one owned handle.
        OwnedHandle::from_raw_handle(result)
    })
}
/// Copies an independently encoded descriptor into naturally aligned native storage.
/// # Errors
/// Returns invalid fixture layout.
fn descriptor(mode: u16, user: Sid, group: Sid, owner: u32) -> io::Result<[u32; 122]> {
    let table = IdentityMap::new(
        vec![UserMapping {
            sid: user,
            uid: Ext4Uid::from_u32(1000),
        }],
        vec![GroupMapping {
            sid: group,
            gid: Ext4Gid::from_u32(100),
        }],
    )
    .map_err(invalid)?;
    let security = Ext4Security::new(
        Ext4Owner::new(Ext4Uid::from_u32(owner), Ext4Gid::from_u32(100)),
        Ext4Permissions::new(mode).map_err(|error| io::Error::other(format!("{error:?}")))?,
    );
    let image = Descriptor::encode(security, &table, Components::ALL).map_err(invalid)?;
    let mut words = [0_u32; 122];
    for (target, chunk) in words.iter_mut().zip(image.bytes().as_chunks::<4>().0) {
        *target = u32::from_le_bytes(*chunk);
    }
    Ok(words)
}
/// Normal access check; expected refusals and execution failures remain distinct.
/// # Errors
/// Propagates native resource or invalid-token failures.
fn check(image: &[u32; 122], token: &OwnedHandle, requested: u32) -> io::Result<AccessDecision> {
    let mapping = GENERIC_MAPPING {
        GenericRead: 0x0012_0089,
        GenericWrite: 0x0012_0116,
        GenericExecute: 0x0012_00a0,
        GenericAll: 0x001f_01ff,
    };
    let mut desired = requested;
    unsafe {
        // SAFETY: Both mapped mask and generic mapping are initialized native storage.
        MapGenericMask(&mut desired, &mapping);
    }
    let mut privileges = [0_u64; 64];
    let mut length = 512_u32;
    let mut granted = 0;
    let mut accepted = 0;
    let success = unsafe {
        // SAFETY: Descriptor and privilege storage are aligned, bounded and retained; token is an impersonation token.
        AccessCheck(
            image.as_ptr().cast_mut().cast(),
            token.as_raw_handle(),
            desired,
            &mapping,
            privileges.as_mut_ptr().cast(),
            &mut length,
            &mut granted,
            &mut accepted,
        )
    };
    if success == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(if accepted != 0 {
        AccessDecision::Granted(granted)
    } else {
        AccessDecision::Denied(-1_073_741_790)
    })
}
/// Makes a token whose group is deny-only, or whose restricted pass must match the user SID.
/// # Errors
/// Returns native restricted-token construction failure.
fn restricted(token: &OwnedHandle, sid: Sid, deny_only: bool) -> io::Result<OwnedHandle> {
    let mut words = [0_u32; 17];
    for (target, chunk) in words.iter_mut().zip(sid.bytes().as_chunks::<4>().0) {
        *target = u32::from_le_bytes(*chunk);
    }
    let principal = SID_AND_ATTRIBUTES {
        Sid: words.as_mut_ptr().cast(),
        Attributes: 0,
    };
    let mut result = ptr::null_mut();
    let success = unsafe {
        // SAFETY: Input token and complete aligned SID remain live; output receives one new token.
        CreateRestrictedToken(
            token.as_raw_handle(),
            DISABLE_MAX_PRIVILEGE,
            u32::from(deny_only),
            if deny_only { &principal } else { ptr::null() },
            0,
            ptr::null(),
            u32::from(!deny_only),
            if deny_only { ptr::null() } else { &principal },
            &mut result,
        )
    };
    if success == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe {
        // SAFETY: Successful construction transfers the distinct token handle.
        OwnedHandle::from_raw_handle(result)
    })
}
/// # Errors
/// Returns oracle setup or native execution failure.
/// # Panics
/// Panics if the Windows observable class and maximum-right contracts differ.
#[expect(
    clippy::panic_in_result_fn,
    reason = "native oracle failures propagate while assertions compare independently specified permission vectors"
)]
#[test]
fn native_owner_group_priority_and_maximum_rights() -> io::Result<()> {
    let source = process_token()?;
    let user = token_sid(&source, TokenUser)?;
    let group = token_sid(&source, TokenPrimaryGroup)?;
    let token = impersonation(&source)?;
    let owner640 = descriptor(0o640, user, group, 1000)?;
    assert!(matches!(
        check(&owner640, &token, 2)?,
        AccessDecision::Granted(_)
    ));
    let maximum = evaluate_access(MAXIMUM_ALLOWED, 0, |right, _| {
        check(&owner640, &token, right)
    })?;
    assert!(
        matches!(maximum, AccessDecision::Granted(mask) if mask & WRITE_RIGHTS == WRITE_RIGHTS)
    );
    let group640 = descriptor(0o640, user, group, 2000)?;
    assert!(matches!(
        check(&group640, &token, 1)?,
        AccessDecision::Granted(_)
    ));
    assert!(
        matches!(evaluate_access(MAXIMUM_ALLOWED, 0, |right, _| check(&group640, &token, right))?, AccessDecision::Granted(mask) if mask & WRITE_RIGHTS == 0)
    );
    assert!(matches!(
        evaluate_access(MAXIMUM_ALLOWED | 2, 0, |right, _| check(
            &group640, &token, right
        ))?,
        AccessDecision::Denied(_)
    ));
    for (mode, generic) in [(0o444, 0x8000_0000), (0o222, 0x4000_0000)] {
        assert!(matches!(
            check(&descriptor(mode, user, group, 1000)?, &token, generic)?,
            AccessDecision::Granted(_)
        ));
    }
    for (mode, owner, right) in [(0o047, 1000, 1), (0o407, 1000, 2), (0o607, 2000, 1)] {
        assert!(matches!(
            check(&descriptor(mode, user, group, owner)?, &token, right)?,
            AccessDecision::Denied(_)
        ));
    }
    assert!(matches!(
        check(&owner640, &token, 0x40000)?,
        AccessDecision::Granted(_)
    ));
    let limited = impersonation(&restricted(&source, user, false)?)?;
    assert!(matches!(
        check(&owner640, &limited, 2)?,
        AccessDecision::Granted(_)
    ));
    assert!(matches!(
        check(&owner640, &limited, 0x80000)?,
        AccessDecision::Denied(_)
    ));
    assert!(matches!(
        check(&owner640, &limited, 0x1000000)?,
        AccessDecision::Denied(_)
    ));
    let deny = impersonation(&restricted(&source, group, true)?)?;
    assert!(matches!(
        check(&owner640, &deny, 2)?,
        AccessDecision::Granted(_)
    ));
    assert!(matches!(
        check(&group640, &deny, 1)?,
        AccessDecision::Denied(_)
    ));
    let success = unsafe {
        // SAFETY: Only this test thread's token changes; the token is retained through explicit restoration.
        SetThreadToken(ptr::null(), token.as_raw_handle())
    };
    if success == 0 {
        return Err(io::Error::last_os_error());
    }
    let observed = effective_identity();
    let restored = unsafe {
        // SAFETY: Balances the preceding thread-local impersonation before any fallible assertion.
        RevertToSelf()
    };
    if restored == 0 {
        return Err(io::Error::last_os_error());
    }
    assert_eq!(observed?.user, user);
    Ok(())
}

/// Selects enabled state for exactly one privilege on a private duplicated token.
/// # Errors
/// Returns lookup, adjustment or privilege-not-assigned failure.
fn set_privilege(token: &OwnedHandle, name: &str, enabled: bool) -> io::Result<()> {
    let name = wide(OsStr::new(name))?;
    let mut luid = windows_sys::Win32::Foundation::LUID::default();
    let found = unsafe {
        // SAFETY: The terminated privilege name and writable LUID live throughout the call.
        LookupPrivilegeValueW(ptr::null(), name.as_ptr(), &mut luid)
    };
    if found == 0 {
        return Err(io::Error::last_os_error());
    }
    let privileges = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: if enabled { SE_PRIVILEGE_ENABLED } else { 0 },
        }],
    };
    unsafe {
        // SAFETY: Clears this thread's last-error observation before the adjustment API.
        windows_sys::Win32::Foundation::SetLastError(0);
    }
    let adjusted = unsafe {
        // SAFETY: Only the private duplicate token is adjusted; input includes its one complete privilege.
        AdjustTokenPrivileges(
            token.as_raw_handle(),
            0,
            &privileges,
            0,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    let error = io::Error::last_os_error();
    if adjusted == 0 || error.raw_os_error() == Some(1300) {
        Err(error)
    } else {
        Ok(())
    }
}
/// # Errors
/// Requires an elevated token containing SeTakeOwnershipPrivilege and SeSecurityPrivilege.
/// # Panics
/// Panics if explicit privileged rights fail or maximum exploration includes them.
#[expect(
    clippy::panic_in_result_fn,
    reason = "native privilege admission errors propagate while assertions verify explicit-only rights"
)]
#[test]
#[ignore = "requires an elevated Windows token with ownership and security privileges"]
fn native_explicit_privileges_contract() -> io::Result<()> {
    let source = process_token()?;
    let user = token_sid(&source, TokenUser)?;
    let group = token_sid(&source, TokenPrimaryGroup)?;
    let token = impersonation(&source)?;
    set_privilege(&token, "SeTakeOwnershipPrivilege", true)?;
    set_privilege(&token, "SeSecurityPrivilege", true)?;
    let image = descriptor(0o640, user, group, 2000)?;
    assert!(matches!(
        check(&image, &token, 0x80000)?,
        AccessDecision::Granted(_)
    ));
    assert!(matches!(
        check(&image, &token, 0x1000000)?,
        AccessDecision::Granted(_)
    ));
    assert!(
        matches!(evaluate_access(MAXIMUM_ALLOWED, 0, |right, _| check(&image, &token, right))?, AccessDecision::Granted(mask) if mask & (0x80000 | 0x1000000) == 0)
    );
    assert!(
        matches!(evaluate_access(MAXIMUM_ALLOWED | 0x1080000, 0, |right, _| check(&image, &token, right))?, AccessDecision::Granted(mask) if mask & 0x1080000 == 0x1080000)
    );
    Ok(())
}

/// # Errors
/// Requires an elevated token containing backup and restore privileges.
/// # Panics
/// Panics if native privilege evaluation treats a disabled privilege as operation authority.
#[test]
#[ignore = "requires an elevated Windows token with backup and restore privileges"]
#[expect(
    clippy::panic_in_result_fn,
    reason = "token errors propagate; assertions verify native privilege authority"
)]
fn native_backup_restore_privileges_contract() -> io::Result<()> {
    let source = process_token()?;
    let token = impersonation(&source)?;
    for name in ["SeBackupPrivilege", "SeRestorePrivilege"] {
        let mut luid = windows_sys::Win32::Foundation::LUID::default();
        let wide_name = wide(OsStr::new(name))?;
        if unsafe {
            // SAFETY: The terminated name and exclusive output LUID remain live during lookup.
            LookupPrivilegeValueW(ptr::null(), wide_name.as_ptr(), &mut luid)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        for enabled in [false, true] {
            set_privilege(&token, name, enabled)?;
            let mut required = PRIVILEGE_SET {
                PrivilegeCount: 1,
                Control: 1, // PRIVILEGE_SET_ALL_NECESSARY
                Privilege: [LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: 0,
                }],
            };
            let mut granted = 0;
            if unsafe {
                // SAFETY: A uniquely owned impersonation token and complete aligned privilege
                // request remain live; native code initializes the exclusive decision output.
                PrivilegeCheck(token.as_raw_handle(), &mut required, &mut granted)
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            assert_eq!(granted != 0, enabled);
        }
    }
    Ok(())
}
