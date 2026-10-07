//! Existing-volume publication and reconciliation against Mount Manager's name authority.
//!
//! Messages and storage are prepared before arrival notification. Failed arrival is an uncertain
//! outcome: exact-name observation resolves it. Every later attempt queries first; shared mount
//! points are never removed as rollback.

use wdk_sys::NTSTATUS;

/// Exact-name registration observation; transport failure is a separate result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Registration {
    /// Mount Manager already owns this target's registration.
    Present,
    /// A valid exact-name query reports an unregistered target.
    Absent,
}

/// Interprets exact-name queries whose input layout, lengths and alignment are already valid.
/// Under that precondition INVALID_PARAMETER reports name absence; transport failure does not.
/// # Errors
/// Preserves transport failures, which cannot establish registration absence.
fn registration(status: NTSTATUS) -> Result<Registration, NTSTATUS> {
    match status {
        wdk_sys::STATUS_BUFFER_OVERFLOW => Ok(Registration::Present),
        wdk_sys::STATUS_INVALID_PARAMETER => Ok(Registration::Absent),
        status if status >= wdk_sys::STATUS_SUCCESS => Ok(Registration::Present),
        status => Err(status),
    }
}

/// Publication resolves acceptance through observation; successful notification alone is insufficient.
/// # Errors
/// Returns pre-publication query failure or unconfirmed acceptance after notification.
fn reconcile_arrival(
    mut query: impl FnMut() -> Result<Registration, NTSTATUS>,
    arrive: impl FnOnce() -> NTSTATUS,
) -> Result<(), NTSTATUS> {
    if query()? == Registration::Present {
        return Ok(());
    }
    let arrival = arrive();
    match query() {
        Ok(Registration::Present) => Ok(()),
        _ if arrival >= wdk_sys::STATUS_SUCCESS => Err(wdk_sys::STATUS_DEVICE_NOT_READY),
        _ => Err(arrival),
    }
}

#[cfg(not(test))]
/// Referenced Windows endpoint and checked mount-device wire exchanges.
mod native {
    use super::*;
    use crate::{
        kernel::{device_interface::unicode_string, ffi},
        memory::{self, DriverVec},
        state::KernelDevice,
    };
    use core::{ffi::c_void, ptr::NonNull};

    /// Mount-device name query, defined by the Windows mount-device protocol.
    const QUERY_DEVICE_NAME: u32 = 0x004d_0008;
    /// Mount Manager exact target-name registration query.
    const QUERY_POINTS: u32 = 0x006d_0008;
    /// Notification publishing the existing lower target's arrival.
    const VOLUME_ARRIVAL: u32 = 0x006d_402c;
    /// Fixed MOUNTMGR_MOUNT_POINT wire prefix, including alignment padding.
    const QUERY_PREFIX: usize = 24;
    /// Mount Manager owns this endpoint independently of the filesystem driver.
    const MANAGER_NAME: &[u16] = &[
        92, 68, 101, 118, 105, 99, 101, 92, 77, 111, 117, 110, 116, 80, 111, 105, 110, 116, 77, 97,
        110, 97, 103, 101, 114, 0,
    ];

    /// One referenced Mount Manager endpoint retained through all publication observations.
    struct Manager {
        /// The FILE_OBJECT reference retains the device returned by the same acquisition.
        file: NonNull<wdk_sys::FILE_OBJECT>,
        /// Endpoint identity borrowed under `file`'s reference.
        device: KernelDevice,
    }

    impl Manager {
        /// Opens observation/notification access without changing Mount Manager state.
        /// # Errors
        /// Returns the native open failure or malformed endpoint identity.
        #[expect(
            unsafe_code,
            reason = "the reference owner encloses every endpoint operation and final release"
        )]
        fn open() -> Result<Self, NTSTATUS> {
            let mut name = unicode_string(MANAGER_NAME)?;
            let mut file = core::ptr::null_mut();
            let mut device = core::ptr::null_mut();
            let status = unsafe {
                // SAFETY: Static terminated name and exclusive local outputs remain live.
                ffi::IoGetDeviceObjectPointer(
                    &mut name,
                    wdk_sys::FILE_READ_ATTRIBUTES,
                    &mut file,
                    &mut device,
                )
            };
            if status < wdk_sys::STATUS_SUCCESS {
                return Err(status);
            }
            let file = NonNull::new(file).ok_or(wdk_sys::STATUS_INTERNAL_ERROR)?;
            let device = unsafe {
                // SAFETY: The successful FILE_OBJECT reference retains this returned device.
                KernelDevice::from_raw(device)
            };
            match device {
                Some(device) => Ok(Self { file, device }),
                None => {
                    unsafe {
                        // SAFETY: Failed construction owns the one successful file acquisition.
                        ffi::ObfDereferenceObject(file.as_ptr().cast());
                    }
                    Err(wdk_sys::STATUS_INTERNAL_ERROR)
                }
            }
        }
    }

    #[expect(
        unsafe_code,
        reason = "this owner balances its single Object Manager reference after all exchanges"
    )]
    impl Drop for Manager {
        fn drop(&mut self) {
            unsafe {
                // SAFETY: No endpoint borrow survives this synchronous protocol owner.
                ffi::ObfDereferenceObject(self.file.as_ptr().cast());
            }
        }
    }

    /// Exchanges owned byte images synchronously; no native pointer escapes completion.
    #[expect(
        unsafe_code,
        reason = "input and output are exclusively borrowed through the native final-completion wait"
    )]
    fn ioctl(
        device: KernelDevice,
        code: u32,
        input: &[u8],
        output: &mut [u8],
    ) -> (NTSTATUS, usize) {
        let Ok(input_length) = u32::try_from(input.len()) else {
            return (wdk_sys::STATUS_INVALID_BUFFER_SIZE, 0);
        };
        let Ok(output_length) = u32::try_from(output.len()) else {
            return (wdk_sys::STATUS_INVALID_BUFFER_SIZE, 0);
        };
        let mut transferred = 0;
        let status = unsafe {
            // SAFETY: Owned images and retained device remain live until final completion.
            ext4win_discovery_ioctl(
                device.as_ptr(),
                code,
                input.as_ptr().cast_mut().cast(),
                input_length,
                output.as_mut_ptr().cast(),
                output_length,
                &mut transferred,
            )
        };
        (status, transferred)
    }

    /// Captures the existing lower stack name and rejects a changing or malformed response.
    /// # Errors
    /// Returns native query, malformed name, or allocation failure before publication.
    fn device_name(device: KernelDevice) -> Result<DriverVec<u8>, NTSTATUS> {
        let mut prefix = [0_u8; 4];
        let (status, transferred) = ioctl(device, QUERY_DEVICE_NAME, &[], &mut prefix);
        if status != wdk_sys::STATUS_BUFFER_OVERFLOW && status < wdk_sys::STATUS_SUCCESS {
            return Err(status);
        }
        let length = u16::from_le_bytes([prefix[0], prefix[1]]);
        if transferred < 2 || length == 0 || length % 2 != 0 {
            return Err(wdk_sys::STATUS_OBJECT_NAME_INVALID);
        }
        let size = usize::from(length)
            .checked_add(2)
            .ok_or(wdk_sys::STATUS_INVALID_BUFFER_SIZE)?;
        let mut name = DriverVec::try_repeated_copy(0, size).map_err(|error| error.ntstatus())?;
        let (status, transferred) = ioctl(device, QUERY_DEVICE_NAME, &[], name.as_mut_slice());
        if status < wdk_sys::STATUS_SUCCESS {
            return Err(status);
        }
        let bytes = name.as_slice();
        if transferred < size || bytes.get(..2) != Some(length.to_le_bytes().as_slice()) {
            return Err(wdk_sys::STATUS_OBJECT_NAME_INVALID);
        }
        Ok(name)
    }

    /// Constructs a complete zeroed query/notification image with checked wire offsets.
    /// # Errors
    /// Returns allocation or invalid wire-range failure, always before notification.
    fn message(prefix: usize, name: &[u8]) -> Result<DriverVec<u8>, NTSTATUS> {
        let size = prefix
            .checked_add(name.len())
            .ok_or(wdk_sys::STATUS_INVALID_BUFFER_SIZE)?;
        let mut image = DriverVec::try_repeated_copy(0, size).map_err(|error| error.ntstatus())?;
        let destination = image
            .as_mut_slice()
            .get_mut(prefix..)
            .ok_or(wdk_sys::STATUS_INTERNAL_ERROR)?;
        memory::copy_exact(destination, name).map_err(|error| error.ntstatus())?;
        Ok(image)
    }

    /// Publishes only the existing lower device, reconciling repeated or uncertain acceptance.
    /// # Errors
    /// Returns preparation failure or an unconfirmed registration outcome; an error never authorizes rollback.
    #[inline(never)] // Retains the publication owner in the signed-artifact reachability boundary.
    pub(in crate::kernel) fn announce_volume_arrival(device: KernelDevice) -> Result<(), NTSTATUS> {
        let name = device_name(device)?;
        let bytes = name
            .as_slice()
            .get(2..)
            .ok_or(wdk_sys::STATUS_INTERNAL_ERROR)?;
        let length = u16::try_from(bytes.len()).map_err(|_| wdk_sys::STATUS_INVALID_BUFFER_SIZE)?;
        let mut query = message(QUERY_PREFIX, bytes)?;
        memory::copy_exact(
            query
                .as_mut_slice()
                .get_mut(16..20)
                .ok_or(wdk_sys::STATUS_INTERNAL_ERROR)?,
            &24_u32.to_le_bytes(),
        )
        .map_err(|error| error.ntstatus())?;
        memory::copy_exact(
            query
                .as_mut_slice()
                .get_mut(20..22)
                .ok_or(wdk_sys::STATUS_INTERNAL_ERROR)?,
            &length.to_le_bytes(),
        )
        .map_err(|error| error.ntstatus())?;
        let mut target = message(2, bytes)?;
        memory::copy_exact(
            target
                .as_mut_slice()
                .get_mut(..2)
                .ok_or(wdk_sys::STATUS_INTERNAL_ERROR)?,
            &length.to_le_bytes(),
        )
        .map_err(|error| error.ntstatus())?;
        let manager = Manager::open()?;
        reconcile_arrival(
            || {
                let mut points = [0_u8; 32];
                registration(ioctl(manager.device, QUERY_POINTS, query.as_slice(), &mut points).0)
            },
            || ioctl(manager.device, VOLUME_ARRIVAL, target.as_slice(), &mut []).0,
        )
    }

    #[expect(
        unsafe_code,
        reason = "the native transport owns only one synchronous IRP and its final-completion wait"
    )]
    unsafe extern "system" {
        fn ext4win_discovery_ioctl(
            device: wdk_sys::PDEVICE_OBJECT,
            code: u32,
            input: *mut c_void,
            input_length: u32,
            output: *mut c_void,
            output_length: u32,
            transferred: *mut usize,
        ) -> NTSTATUS;
    }
}

#[cfg(not(test))]
pub(super) use native::announce_volume_arrival;

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    /// # Panics
    /// Fails if transport failure publishes an arrival or ambiguous acceptance is blindly retried.
    #[test]
    fn publication_requires_exact_registration_observation() {
        let arrivals = Cell::new(0);
        assert_eq!(
            registration(wdk_sys::STATUS_INVALID_PARAMETER),
            Ok(Registration::Absent)
        );
        assert_eq!(
            registration(wdk_sys::STATUS_BUFFER_OVERFLOW),
            Ok(Registration::Present)
        );
        assert_eq!(
            registration(wdk_sys::STATUS_ACCESS_DENIED),
            Err(wdk_sys::STATUS_ACCESS_DENIED)
        );
        assert_eq!(
            reconcile_arrival(
                || Err(wdk_sys::STATUS_ACCESS_DENIED),
                || {
                    arrivals.set(1);
                    wdk_sys::STATUS_SUCCESS
                }
            ),
            Err(wdk_sys::STATUS_ACCESS_DENIED)
        );
        assert_eq!(arrivals.get(), 0);
        let queried = Cell::new(false);
        assert_eq!(
            reconcile_arrival(
                || {
                    let repeated = queried.replace(true);
                    Ok(if !repeated {
                        Registration::Absent
                    } else {
                        Registration::Present
                    })
                },
                || {
                    arrivals.set(1);
                    wdk_sys::STATUS_IO_TIMEOUT
                }
            ),
            Ok(())
        );
        assert_eq!(arrivals.get(), 1);
        assert_eq!(
            reconcile_arrival(|| Ok(Registration::Absent), || wdk_sys::STATUS_SUCCESS),
            Err(wdk_sys::STATUS_DEVICE_NOT_READY)
        );
    }
}
