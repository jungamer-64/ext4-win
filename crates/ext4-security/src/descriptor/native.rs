//! Shared kernel/user RTL boundary. The final executable supplies its native import library;
//! this library never introduces a user-mode import into a kernel driver.
//! Kernel constructors run in the PASSIVE_LEVEL filesystem actor; user-mode callers use ntdll.
use super::{AceKind, Components};
use crate::{Error, Sid, reserve};
use alloc::vec::Vec;
use core::{ffi::c_void, ptr};

/// DWORD-aligned, initialized storage for a native ACL or self-relative descriptor.
#[derive(Debug)]
pub(super) struct NativeImage {
    /// Allocation alignment is independent of the global allocator's minimum alignment.
    words: Vec<u32>,
    /// Exact initialized native byte length, excluding allocation padding.
    length: usize,
}

impl NativeImage {
    /// # Errors
    /// Returns size overflow or physical allocation failure.
    fn zeroed(length: usize) -> Result<Self, Error> {
        let count = length.checked_add(3).ok_or(Error::RecordTooLarge)? / 4;
        let mut words = Vec::new();
        reserve(&mut words, count)?;
        words.resize(count, 0);
        Ok(Self { words, length })
    }

    /// All backing words are initialized; no pointer escapes the owning descriptor.
    #[expect(
        unsafe_code,
        reason = "the bounded byte view borrows initialized DWORD storage"
    )]
    pub(super) fn bytes(&self) -> &[u8] {
        unsafe {
            // SAFETY: length never exceeds initialized word storage; the borrow retains it.
            core::slice::from_raw_parts(self.words.as_ptr().cast(), self.length)
        }
    }

    /// Returns uniquely borrowed, aligned native output storage.
    fn as_mut_ptr(&mut self) -> *mut c_void {
        self.words.as_mut_ptr().cast()
    }

    /// All component storage remains live and immutable until RTL has copied it.
    /// # Errors
    /// Returns allocation, size or exact RTL failure without publishing a partial image.
    #[expect(
        unsafe_code,
        reason = "one synchronous RTL construction owns every input and output"
    )]
    pub(super) fn build(
        owner: Sid,
        group: Sid,
        acl: Option<&NativeAcl>,
        selection: Components,
    ) -> Result<Self, Error> {
        let mut absolute = AbsoluteDescriptor {
            revision: 0,
            reserved: 0,
            control: 0,
            owner: ptr::null_mut(),
            group: ptr::null_mut(),
            sacl: ptr::null_mut(),
            dacl: ptr::null_mut(),
        };
        let owner = AlignedSid::new(owner);
        let group = AlignedSid::new(group);
        let descriptor = ptr::addr_of_mut!(absolute).cast();
        native(unsafe {
            // SAFETY: repr(C) storage matches SECURITY_DESCRIPTOR and is exclusively writable.
            // Kernel construction is owned by the PASSIVE_LEVEL filesystem actor.
            create_descriptor(descriptor, 1)
        })?;
        if selection.bits() & 1 != 0 {
            native(unsafe {
                // SAFETY: owner is an aligned validated SID retained through conversion.
                set_owner(descriptor, owner.as_ptr(), 0)
            })?;
        }
        if selection.bits() & 2 != 0 {
            native(unsafe {
                // SAFETY: group is an aligned validated SID retained through conversion.
                set_group(descriptor, group.as_ptr(), 0)
            })?;
        }
        if let Some(acl) = acl {
            native(unsafe {
                // SAFETY: RTL initialized this complete aligned ACL; it outlives conversion.
                set_dacl(descriptor, 1, acl.image.words.as_ptr().cast_mut().cast(), 0)
            })?;
        }
        let mut length = 0_u32;
        let status = unsafe {
            // SAFETY: a zero-sized output requests the required length without writing bytes.
            make_relative(descriptor, ptr::null_mut(), &mut length)
        };
        if status != i32::from_ne_bytes(0xC000_0023_u32.to_ne_bytes()) {
            native(status)?;
            return Err(Error::InvalidEncoding);
        }
        let mut image = Self::zeroed(usize::try_from(length).map_err(|_| Error::RecordTooLarge)?)?;
        native(unsafe {
            // SAFETY: the measured, aligned output is uniquely owned; all components remain live.
            make_relative(descriptor, image.as_mut_ptr(), &mut length)
        })?;
        image.length = usize::try_from(length).map_err(|_| Error::RecordTooLarge)?;
        Ok(image)
    }
}

/// The native ACL owns entry placement, entry count and revision/length fields.
pub(super) struct NativeAcl {
    /// Immutable after the projection has finished adding entries.
    image: NativeImage,
}
impl NativeAcl {
    /// # Errors
    /// Returns length, allocation or native initialization failure.
    #[expect(
        unsafe_code,
        reason = "RTL receives the exact initialized aligned ACL allocation"
    )]
    pub(super) fn new(length: usize) -> Result<Self, Error> {
        let mut image = NativeImage::zeroed(length)?;
        native(unsafe {
            // SAFETY: the allocation is aligned and writable for the checked byte length.
            create_acl(
                image.as_mut_ptr(),
                u32::try_from(length).map_err(|_| Error::RecordTooLarge)?,
                2,
            )
        })?;
        Ok(Self { image })
    }

    /// Append preserves the caller's semantic order, including intentional allow-before-deny.
    /// # Errors
    /// Returns an ACE length or exact native append failure.
    #[expect(
        unsafe_code,
        reason = "RTL copies one bounded typed ACE into an exclusively owned ACL"
    )]
    pub(super) fn push(&mut self, kind: AceKind, mask: u32, sid: Sid) -> Result<(), Error> {
        let length = u16::try_from(
            8_usize
                .checked_add(sid.bytes().len())
                .ok_or(Error::RecordTooLarge)?,
        )
        .map_err(|_| Error::RecordTooLarge)?;
        let mut ace = PlainAce {
            kind: match kind {
                AceKind::Allow => 0,
                AceKind::Deny => 1,
            },
            flags: 0,
            length,
            mask,
            sid: [0; 68],
        };
        for (target, source) in ace.sid.iter_mut().zip(sid.bytes()) {
            *target = *source;
        }
        native(unsafe {
            // SAFETY: repr(C) supplies the plain ACE ABI; its validated SID and exact length
            // are initialized. RTL copies the ACE synchronously and retains no stack pointer.
            add_ace(
                self.image.as_mut_ptr(),
                2,
                u32::MAX,
                ptr::addr_of_mut!(ace).cast(),
                u32::from(length),
            )
        })
    }
}

/// Absolute SECURITY_DESCRIPTOR ABI; pointed-to components stay owned by build's frame.
#[repr(C)]
struct AbsoluteDescriptor {
    /// Native ABI fields are initialized and interpreted exclusively by RTL.
    revision: u8,
    /// Native reserved byte.
    reserved: u8,
    /// Native control flags.
    control: u16,
    /// Borrowed owner SID.
    owner: *mut c_void,
    /// Borrowed primary-group SID.
    group: *mut c_void,
    /// Borrowed audit ACL.
    sacl: *mut c_void,
    /// Borrowed access ACL.
    dacl: *mut c_void,
}

/// ACCESS_ALLOWED_ACE / ACCESS_DENIED_ACE share this fixed header and trailing SID ABI.
#[repr(C)]
struct PlainAce {
    /// Native allow/deny tag.
    kind: u8,
    /// Explicit ACE with no inheritance flags.
    flags: u8,
    /// Exact bytes including the variable SID prefix.
    length: u16,
    /// Specific access mask.
    mask: u32,
    /// Initialized variable SID storage; only length bytes are passed to RTL.
    sid: [u8; 68],
}

/// DWORD alignment is required even when the portable SID's representation is byte-aligned.
#[repr(C, align(4))]
struct AlignedSid(
    /// Complete maximum SID storage; the SID header determines its initialized prefix.
    [u8; 68],
);
impl AlignedSid {
    /// Copies a validated SID into stack-owned native storage.
    fn new(sid: Sid) -> Self {
        let mut value = Self([0; 68]);
        for (target, source) in value.0.iter_mut().zip(sid.bytes()) {
            *target = *source;
        }
        value
    }
    /// RTL borrows and does not modify the SID.
    fn as_ptr(&self) -> *mut c_void {
        self.0.as_ptr().cast_mut().cast()
    }
}

/// # Errors
/// Preserves the exact failing NTSTATUS for the caller's native completion boundary.
fn native(status: i32) -> Result<(), Error> {
    if status < 0 {
        Err(Error::NativeFailure(status))
    } else {
        Ok(())
    }
}

#[expect(
    unsafe_code,
    reason = "the shared RTL ABI resolves to ntoskrnl or ntdll at the executable boundary"
)]
unsafe extern "system" {
    /// Initializes writable absolute SECURITY_DESCRIPTOR storage.
    #[link_name = "RtlCreateSecurityDescriptor"]
    fn create_descriptor(descriptor: *mut c_void, revision: u32) -> i32;
    /// Borrows a validated aligned SID until the absolute descriptor is converted.
    #[link_name = "RtlSetOwnerSecurityDescriptor"]
    fn set_owner(descriptor: *mut c_void, sid: *mut c_void, defaulted: u8) -> i32;
    /// Borrows a validated aligned group SID until conversion.
    #[link_name = "RtlSetGroupSecurityDescriptor"]
    fn set_group(descriptor: *mut c_void, sid: *mut c_void, defaulted: u8) -> i32;
    /// Borrows a complete initialized ACL until conversion.
    #[link_name = "RtlSetDaclSecurityDescriptor"]
    fn set_dacl(descriptor: *mut c_void, present: u8, acl: *mut c_void, defaulted: u8) -> i32;
    /// Measures or copies into caller-owned aligned descriptor storage.
    #[link_name = "RtlAbsoluteToSelfRelativeSD"]
    fn make_relative(absolute: *mut c_void, relative: *mut c_void, length: *mut u32) -> i32;
    /// Initializes the exact writable ACL allocation.
    #[link_name = "RtlCreateAcl"]
    fn create_acl(acl: *mut c_void, length: u32, revision: u32) -> i32;
    /// Copies the bounded plain ACE at the selected insertion point.
    #[link_name = "RtlAddAce"]
    fn add_ace(acl: *mut c_void, revision: u32, index: u32, ace: *mut c_void, length: u32) -> i32;
}
