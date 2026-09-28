using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Ext4Win {
    // Metadata-only opens participate in handle lifetime even when native share counters stay zero.
    public static class LiveMetadata {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFile(string name, uint access, uint share,
            IntPtr security, uint disposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetVolumeInformationByHandleW(SafeFileHandle handle,
            StringBuilder label, uint labelLength, out uint serial, out uint maximum,
            out uint flags, StringBuilder filesystem, uint filesystemLength);

        public static void Verify(string file) {
            // Attribute-only and zero-access handles must survive independent cleanup while a
            // subsequent data open remains valid. No handle requests mutation authority.
            using (var first = CreateFile(file, 0x80, 7, IntPtr.Zero, 3, 0, IntPtr.Zero)) {
                if (first.IsInvalid) { throw new Win32Exception(Marshal.GetLastWin32Error()); }
                using (var second = CreateFile(file, 0, 7, IntPtr.Zero, 3, 0, IntPtr.Zero)) {
                    if (second.IsInvalid) { throw new Win32Exception(Marshal.GetLastWin32Error()); }
                    var label = new StringBuilder(261);
                    var filesystem = new StringBuilder(261);
                    uint serial, maximum, flags;
                    if (!GetVolumeInformationByHandleW(second, label, 261, out serial,
                        out maximum, out flags, filesystem, 261)) {
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    }
                    if (filesystem.ToString() != "EXT4WIN" || maximum != 255) {
                        throw new InvalidOperationException("volume identity from metadata handle differs");
                    }
                }
                using (var data = CreateFile(file, 0x80000000, 7, IntPtr.Zero, 3, 0, IntPtr.Zero)) {
                    if (data.IsInvalid) { throw new Win32Exception(Marshal.GetLastWin32Error()); }
                }
            }
        }
    }

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

    // Exercises the native FILE_NAMES_INFORMATION contract against the disposable fixture.
    public static class LiveDirectory {
        [StructLayout(LayoutKind.Sequential)]
        private struct IoStatus { public IntPtr Status; public UIntPtr Information; }
        [StructLayout(LayoutKind.Sequential)]
        private struct UnicodeString { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFile(string name, uint access, uint share,
            IntPtr security, uint disposition, uint flags, IntPtr template);
        [DllImport("ntdll.dll")]
        private static extern int NtQueryDirectoryFile(SafeFileHandle file, IntPtr ev,
            IntPtr apc, IntPtr context, out IoStatus status, [Out] byte[] buffer, uint length,
            int informationClass, [MarshalAs(UnmanagedType.U1)] bool single,
            IntPtr pattern, [MarshalAs(UnmanagedType.U1)] bool restart);

        private static SafeFileHandle Open(string path) {
            var handle = CreateFile(path, 0x00100001, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero);
            if (handle.IsInvalid) { handle.Dispose(); throw new Win32Exception(Marshal.GetLastWin32Error()); }
            return handle;
        }
        private static byte[] Query(SafeFileHandle file, string pattern, int capacity, bool single,
            bool restart, uint expectedStatus, out int returned) {
            IntPtr text = IntPtr.Zero;
            IntPtr expression = IntPtr.Zero;
            try {
                if (pattern != null) {
                    text = Marshal.StringToHGlobalUni(pattern);
                    var value = new UnicodeString { Length = checked((ushort)(pattern.Length * 2)),
                        MaximumLength = checked((ushort)((pattern.Length + 1) * 2)), Buffer = text };
                    expression = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UnicodeString)));
                    Marshal.StructureToPtr(value, expression, false);
                }
                byte[] bytes = new byte[capacity];
                IoStatus io;
                uint status = unchecked((uint)NtQueryDirectoryFile(file, IntPtr.Zero, IntPtr.Zero,
                    IntPtr.Zero, out io, bytes, (uint)capacity, 12, single, expression, restart));
                returned = checked((int)io.Information.ToUInt64());
                if (status != expectedStatus || returned > capacity) {
                    throw new InvalidOperationException("QueryDirectory status " + status.ToString("X8") +
                        ", expected " + expectedStatus.ToString("X8") + ", bytes " + returned + ", capacity " + capacity + ", pattern " + pattern + ", restart " + restart);
                }
                return bytes;
            }
            finally {
                if (expression != IntPtr.Zero) { Marshal.FreeHGlobal(expression); }
                if (text != IntPtr.Zero) { Marshal.FreeHGlobal(text); }
            }
        }
        private static void RequireSingle(byte[] bytes, int returned, string expected) {
            if (returned < 12 || BitConverter.ToUInt32(bytes, 0) != 0 ||
                BitConverter.ToUInt32(bytes, 8) != expected.Length * 2 ||
                returned != 12 + expected.Length * 2 ||
                Encoding.Unicode.GetString(bytes, 12, returned - 12) != expected) {
                throw new InvalidOperationException("single FILE_NAMES_INFORMATION record mismatch");
            }
        }
        public static void Verify(string directory) {
            const string name = "entry-000000";
            int returned;
            using (var handle = Open(directory)) {
                var prefix = Query(handle, name, 16, true, false, 0x80000005, out returned);
                if (returned != 16 || BitConverter.ToUInt32(prefix, 8) != name.Length * 2) {
                    throw new InvalidOperationException("initial overflow prefix mismatch: bytes=" + returned + ", name bytes=" + BitConverter.ToUInt32(prefix, 8));
                }
                RequireSingle(Query(handle, "ignored-later-expression", 256, true, false, 0, out returned), returned, name);
                Query(handle, null, 256, true, false, 0x80000006, out returned);
                RequireSingle(Query(handle, null, 256, true, true, 0, out returned), returned, name);
            }
            using (var handle = Open(directory)) {
                Query(handle, "no-such-entry", 256, true, false, 0xC000000F, out returned);
                Query(handle, null, 256, true, false, 0x80000006, out returned);
            }
            using (var handle = Open(directory)) {
                var bytes = Query(handle, "entry-*", 76, false, false, 0, out returned);
                if (returned != 76 || BitConverter.ToUInt32(bytes, 0) != 40 ||
                    BitConverter.ToUInt32(bytes, 40) != 0 ||
                    BitConverter.ToUInt32(bytes, 8) != 24 || BitConverter.ToUInt32(bytes, 48) != 24) {
                    throw new InvalidOperationException("small-buffer record alignment or final link mismatch");
                }
                Query(handle, null, 16, true, false, 0, out returned);
                if (returned != 0) { throw new InvalidOperationException("later short buffer consumed a name"); }
                Query(handle, null, 256, true, false, 0, out returned);
                if (returned != 36) { throw new InvalidOperationException("retry did not return one complete name"); }
            }
        }
    }
}
