using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Ext4Win {
    public enum LiveVolumeMountState {
        Absent,
        Dismounted,
        Mounted,
    }

    // Read-only identity lookup. Discovery must already have registered a volume
    // with Mount Manager; this helper cannot register or retag a partition.
    public static class LiveVolume {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr FindFirstVolume(StringBuilder name, uint length);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool FindNextVolume(IntPtr search, StringBuilder name, uint length);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool FindVolumeClose(IntPtr search);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFile(string name, uint access, uint share,
            IntPtr security, uint disposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeviceIoControl(SafeFileHandle handle, uint code,
            IntPtr input, uint inputLength, byte[] output, uint outputLength,
            out uint returned, IntPtr overlapped);
        [DllImport("kernel32.dll", EntryPoint = "DeviceIoControl", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeviceIoControlWithoutOutput(SafeFileHandle handle, uint code,
            IntPtr input, uint inputLength, IntPtr output, uint outputLength,
            out uint returned, IntPtr overlapped);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetVolumeNameForVolumeMountPoint(string path,
            StringBuilder name, uint length);

        public static string AtMountPoint(string path) {
            var name = new StringBuilder(1024);
            if (!GetVolumeNameForVolumeMountPoint(path, name, (uint)name.Capacity)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            return name.ToString();
        }

        // A dismount acknowledgement can be lost if the host process exits after the FSCTL.
        // Recovery queries the recorded volume rather than treating a repeated failure as proof
        // that the original request did not commit.
        public static LiveVolumeMountState MountState(string volume) {
            using (SafeFileHandle handle = CreateFile(volume.TrimEnd('\\'),
                0x80000000, 7, IntPtr.Zero, 3, 0, IntPtr.Zero)) {
                if (handle.IsInvalid) {
                    return MountStateFromError(Marshal.GetLastWin32Error());
                }
                uint returned;
                // FSCTL_IS_VOLUME_MOUNTED, with no input or output payload.
                if (DeviceIoControlWithoutOutput(handle, 0x00090028,
                    IntPtr.Zero, 0, IntPtr.Zero, 0, out returned, IntPtr.Zero)) {
                    if (returned != 0) {
                        throw new InvalidOperationException(
                            "FSCTL_IS_VOLUME_MOUNTED returned an unexpected payload");
                    }
                    return LiveVolumeMountState.Mounted;
                }
                return MountStateFromError(Marshal.GetLastWin32Error());
            }
        }

        private static LiveVolumeMountState MountStateFromError(int error) {
            // The device path disappears after physical retirement. A logically dismounted
            // volume remains identifiable but rejects mounted-only access with NOT_READY or
            // UNRECOGNIZED_VOLUME.
            if (error == 2 || error == 3) {
                return LiveVolumeMountState.Absent;
            }
            if (error == 21 || error == 1005) {
                return LiveVolumeMountState.Dismounted;
            }
            throw new Win32Exception(error);
        }

        // Match the independently recorded GPT partition ID as well as the disk
        // extent: a removed disk's number may be reused during discovery. No access requests a
        // filesystem mount; inaccessible unrelated volumes are not candidates.
        public static string Find(uint disk, long offset, long length, Guid partitionId) {
            var name = new StringBuilder(1024);
            IntPtr search = FindFirstVolume(name, (uint)name.Capacity);
            if (search == new IntPtr(-1)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            string match = null;
            try {
                do {
                    string volume = name.ToString();
                    using (SafeFileHandle handle = CreateFile(volume.TrimEnd('\\'),
                        0, 7, IntPtr.Zero, 3, 0, IntPtr.Zero)) {
                        if (handle.IsInvalid) { continue; }
                        var extents = new byte[32];
                        uint returned;
                        // IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, one native DISK_EXTENT.
                        if (!DeviceIoControl(handle, 0x00560000, IntPtr.Zero, 0,
                            extents, (uint)extents.Length, out returned, IntPtr.Zero)) {
                            continue;
                        }
                        if (returned != 32 || BitConverter.ToUInt32(extents, 0) != 1 ||
                            BitConverter.ToUInt32(extents, 8) != disk ||
                            BitConverter.ToInt64(extents, 16) != offset ||
                            BitConverter.ToInt64(extents, 24) != length) { continue; }
                        // IOCTL_DISK_GET_PARTITION_INFO_EX. The GPT arm starts at
                        // byte 32; its partition ID follows the 16-byte type GUID.
                        var partition = new byte[144];
                        if (!DeviceIoControl(handle, 0x00070048, IntPtr.Zero, 0,
                            partition, (uint)partition.Length, out returned, IntPtr.Zero) ||
                            returned != 144 || BitConverter.ToUInt32(partition, 0) != 1) { continue; }
                        var identity = new byte[16];
                        Buffer.BlockCopy(partition, 48, identity, 0, identity.Length);
                        if (new Guid(identity) != partitionId) { continue; }
                        if (match != null && match != volume) {
                            throw new InvalidOperationException("multiple volume names match the session partition");
                        }
                        match = volume;
                    }
                } while (FindNextVolume(search, name, (uint)name.Capacity));
                int error = Marshal.GetLastWin32Error();
                if (error != 18) { throw new Win32Exception(error); } // ERROR_NO_MORE_FILES
            }
            finally {
                if (!FindVolumeClose(search)) {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
            }
            return match;
        }
    }
}
