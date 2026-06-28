//! Kernel storage target connected to the ext4-core block-device traits.

use core::ffi::c_void;

use ext4_core::{BlockReader, BlockWriter, ByteOffset, DeviceLength, Error, Result};
use wdk_sys::{
    BOOLEAN, IO_STATUS_BLOCK, IRP_MJ_FLUSH_BUFFERS, IRP_MJ_READ, IRP_MJ_WRITE, KEVENT,
    KPROCESSOR_MODE, LARGE_INTEGER, NTSTATUS, PIRP, PVOID, STATUS_PENDING, STATUS_SUCCESS,
};

use crate::{kernel::ffi, state::KernelDevice};

/// `FALSE` represented as WDK `BOOLEAN`.
const BOOLEAN_FALSE: BOOLEAN = 0;
/// Kernel wait mode for synchronous lower-device requests.
const KERNEL_MODE: KPROCESSOR_MODE = 0;
/// `IOCTL_DISK_GET_LENGTH_INFO` from `winioctl.h`.
const IOCTL_DISK_GET_LENGTH_INFO: wdk_sys::ULONG = 475_228;

/// Output buffer returned by `IOCTL_DISK_GET_LENGTH_INFO`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct DiskLengthInformation {
    /// Device length in bytes.
    length: i64,
}

/// Queries the byte length of a lower storage device.
pub(crate) fn query_device_length(device: KernelDevice) -> Result<DeviceLength> {
    let mut event = KEVENT::default();
    let mut io_status = IO_STATUS_BLOCK::default();
    let mut length = DiskLengthInformation::default();
    initialize_notification_event(&mut event);

    let output_length =
        <wdk_sys::ULONG as TryFrom<usize>>::try_from(core::mem::size_of::<DiskLengthInformation>())
            .map_err(|_| Error::DeviceRange)?;
    let irp = unsafe {
        // SAFETY: The target device is non-null. The output buffer, event, and
        // IOSB are stack locals that outlive the synchronous request.
        ffi::IoBuildDeviceIoControlRequest(
            IOCTL_DISK_GET_LENGTH_INFO,
            device.as_ptr(),
            core::ptr::null_mut(),
            0,
            core::ptr::from_mut(&mut length).cast::<c_void>(),
            output_length,
            BOOLEAN_FALSE,
            core::ptr::from_mut(&mut event),
            core::ptr::from_mut(&mut io_status),
        )
    };
    let information = submit_synchronous_irp(device, irp, &mut event, &io_status)?;
    ensure_expected_information(information, output_length)?;
    device_length_from_information(length)
}

/// Converts disk length query output into the core device-length domain.
fn device_length_from_information(length: DiskLengthInformation) -> Result<DeviceLength> {
    let bytes = u64::try_from(length.length).map_err(|_| Error::DeviceRange)?;
    if bytes == 0 {
        return Err(Error::DeviceRange);
    }
    Ok(DeviceLength::from_bytes(bytes))
}

/// Lower storage device exposed to ext4-core as a checked random-access device.
#[derive(Clone, Copy, Debug)]
pub(crate) struct KernelBlockDevice {
    /// Lower storage device object that receives read/write IRPs.
    device: KernelDevice,
    /// Valid byte range exposed by the storage target.
    length: DeviceLength,
}

impl KernelBlockDevice {
    /// Creates a block-device boundary for a mounted storage target.
    pub(crate) const fn new(device: KernelDevice, length: DeviceLength) -> Self {
        Self { device, length }
    }

    /// Validates a byte range before it crosses into the I/O Manager.
    fn validate_range(self, offset: ByteOffset, len: usize) -> Result<()> {
        let request_len = u64::try_from(len).map_err(|_| Error::DeviceRange)?;
        let end = offset
            .get()
            .checked_add(request_len)
            .ok_or(Error::DeviceRange)?;
        if end > self.length.bytes() {
            return Err(Error::DeviceRange);
        }
        Ok(())
    }

    /// Sends a synchronous read or write IRP to the lower storage device.
    fn transfer(
        self,
        major_function: wdk_sys::ULONG,
        offset: ByteOffset,
        buffer: PVOID,
        len: usize,
    ) -> Result<()> {
        if len == 0 {
            return Ok(());
        }
        self.validate_range(offset, len)?;

        let request_length =
            <wdk_sys::ULONG as TryFrom<usize>>::try_from(len).map_err(|_| Error::DeviceRange)?;
        let starting_offset = i64::try_from(offset.get()).map_err(|_| Error::DeviceRange)?;
        let mut starting_offset = LARGE_INTEGER {
            QuadPart: starting_offset,
        };

        self.send_synchronous_request(
            major_function,
            buffer,
            request_length,
            core::ptr::addr_of_mut!(starting_offset),
        )
    }

    /// Sends a synchronous flush IRP to the lower storage device.
    fn flush_lower_device(self) -> Result<()> {
        self.send_synchronous_request(
            IRP_MJ_FLUSH_BUFFERS,
            core::ptr::null_mut(),
            0,
            core::ptr::null_mut(),
        )
    }

    /// Builds, submits, waits for, and validates a synchronous lower-device IRP.
    fn send_synchronous_request(
        self,
        major_function: wdk_sys::ULONG,
        buffer: PVOID,
        request_length: wdk_sys::ULONG,
        starting_offset: wdk_sys::PLARGE_INTEGER,
    ) -> Result<()> {
        let mut event = KEVENT::default();
        let mut io_status = IO_STATUS_BLOCK::default();
        initialize_notification_event(&mut event);

        let irp = unsafe {
            // SAFETY: The target device is a non-null kernel device object. The
            // buffer and offset pointers are either null for flush or valid for
            // the synchronous request lifetime, and IOSB/event outlive the IRP.
            ffi::IoBuildSynchronousFsdRequest(
                major_function,
                self.device.as_ptr(),
                buffer,
                request_length,
                starting_offset,
                core::ptr::from_mut(&mut event),
                core::ptr::from_mut(&mut io_status),
            )
        };
        let information = submit_synchronous_irp(self.device, irp, &mut event, &io_status)?;
        if request_length != 0 {
            ensure_expected_information(information, request_length)?;
        }

        Ok(())
    }
}

impl BlockReader for KernelBlockDevice {
    fn len(&self) -> DeviceLength {
        self.length
    }

    fn read_exact_at(&self, offset: ByteOffset, out: &mut [u8]) -> Result<()> {
        self.transfer(
            IRP_MJ_READ,
            offset,
            out.as_mut_ptr().cast::<c_void>(),
            out.len(),
        )
    }
}

impl BlockWriter for KernelBlockDevice {
    fn write_exact_at(&mut self, offset: ByteOffset, bytes: &[u8]) -> Result<()> {
        self.transfer(
            IRP_MJ_WRITE,
            offset,
            bytes.as_ptr().cast_mut().cast::<c_void>(),
            bytes.len(),
        )
    }

    fn flush(&mut self) -> Result<()> {
        self.flush_lower_device()
    }
}

/// Initializes a stack event used for one synchronous lower-device request.
fn initialize_notification_event(event: &mut KEVENT) {
    unsafe {
        // SAFETY: `event` is writable stack storage and the event type/state
        // values are the WDK-defined NotificationEvent/FALSE constants.
        ffi::KeInitializeEvent(
            core::ptr::from_mut(event),
            wdk_sys::_EVENT_TYPE::NotificationEvent,
            BOOLEAN_FALSE,
        );
    }
}

/// Submits an already-built synchronous IRP and waits for completion.
fn submit_synchronous_irp(
    device: KernelDevice,
    irp: PIRP,
    event: &mut KEVENT,
    io_status: &IO_STATUS_BLOCK,
) -> Result<wdk_sys::ULONG_PTR> {
    if irp.is_null() {
        return Err(Error::DeviceIo);
    }

    let call_status = unsafe {
        // SAFETY: `irp` was allocated for this non-null lower device object and
        // ownership is transferred to the I/O Manager by IofCallDriver.
        ffi::IofCallDriver(device.as_ptr(), irp)
    };

    if call_status == STATUS_PENDING {
        let wait_status = unsafe {
            // SAFETY: `event` remains alive until the synchronous request
            // completes, timeout is null for an indefinite kernel wait.
            ffi::KeWaitForSingleObject(
                core::ptr::from_mut(event).cast::<c_void>(),
                wdk_sys::_KWAIT_REASON::Executive,
                KERNEL_MODE,
                BOOLEAN_FALSE,
                core::ptr::null_mut(),
            )
        };
        ensure_nt_success(wait_status)?;
    } else {
        ensure_nt_success(call_status)?;
    }

    let final_status = io_status_status(io_status);
    ensure_nt_success(final_status)?;
    Ok(io_status.Information)
}

/// Requires a lower-device request to report the expected transfer size.
fn ensure_expected_information(
    information: wdk_sys::ULONG_PTR,
    expected: wdk_sys::ULONG,
) -> Result<()> {
    if information != <wdk_sys::ULONG_PTR as From<wdk_sys::ULONG>>::from(expected) {
        return Err(Error::DeviceIo);
    }
    Ok(())
}

/// Rejects failing NTSTATUS values.
fn ensure_nt_success(status: NTSTATUS) -> Result<()> {
    if status < STATUS_SUCCESS {
        return Err(Error::DeviceIo);
    }
    Ok(())
}

/// Reads the completed status from an IOSB written by the I/O Manager.
fn io_status_status(io_status: &IO_STATUS_BLOCK) -> NTSTATUS {
    unsafe {
        // SAFETY: The IOSB was initialized and then completed by the I/O Manager;
        // the Status union field is valid after request completion.
        io_status.__bindgen_anon_1.Status
    }
}

#[cfg(test)]
mod tests {
    use core::ffi::c_void;
    use core::ptr::NonNull;

    use ext4_core::{BlockReader, ByteOffset};

    use super::{DiskLengthInformation, KernelBlockDevice, device_length_from_information};
    use crate::state::KernelDevice;

    #[test]
    fn kernel_block_device_preserves_device_and_length() {
        let raw = NonNull::<c_void>::dangling().as_ptr().cast();
        let device = KernelDevice::from_raw(raw);
        assert!(device.is_some());
        let Some(device) = device else {
            return;
        };
        let block_device =
            KernelBlockDevice::new(device, ext4_core::DeviceLength::from_bytes(4096));

        assert_eq!(block_device.len().bytes(), 4096);
        assert_eq!(block_device.device.as_ptr(), raw);
    }

    #[test]
    fn kernel_block_device_rejects_out_of_range_request_before_ffi() {
        let raw = NonNull::<c_void>::dangling().as_ptr().cast();
        let device = KernelDevice::from_raw(raw);
        assert!(device.is_some());
        let Some(device) = device else {
            return;
        };
        let block_device = KernelBlockDevice::new(device, ext4_core::DeviceLength::from_bytes(4));
        let mut output = [0_u8; 2];

        assert_eq!(
            block_device.read_exact_at(ByteOffset::new(3), &mut output),
            Err(ext4_core::Error::DeviceRange)
        );
    }

    #[test]
    fn disk_length_information_rejects_non_positive_lengths() {
        assert_eq!(
            device_length_from_information(DiskLengthInformation { length: 0 }),
            Err(ext4_core::Error::DeviceRange)
        );
        assert_eq!(
            device_length_from_information(DiskLengthInformation { length: -1 }),
            Err(ext4_core::Error::DeviceRange)
        );
    }

    #[test]
    fn disk_length_information_preserves_positive_length() {
        let length = device_length_from_information(DiskLengthInformation { length: 4096 });
        assert!(length.is_ok());
        if let Ok(length) = length {
            assert_eq!(length.bytes(), 4096);
        }
    }
}
