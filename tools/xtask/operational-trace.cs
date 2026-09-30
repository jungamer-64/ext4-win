using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

namespace Ext4Win
{
    // The live host is x64. These layouts are the x64 evntrace.h/evntcons.h ABI;
    // unused output fields retain their native storage rather than a managed projection.
    public sealed class OperationalTraceSession : IDisposable
    {
        [StructLayout(LayoutKind.Explicit, Size = 120)]
        private struct Properties
        {
            [FieldOffset(0)] public uint Size;
            [FieldOffset(24)] public Guid Guid;
            [FieldOffset(40)] public uint Clock;
            [FieldOffset(44)] public uint Flags;
            [FieldOffset(48)] public uint BufferSize;
            [FieldOffset(52)] public uint MinimumBuffers;
            [FieldOffset(56)] public uint MaximumBuffers;
            [FieldOffset(60)] public uint MaximumFileSize;
            [FieldOffset(64)] public uint LogFileMode;
            [FieldOffset(68)] public uint FlushTimer;
            [FieldOffset(88)] public uint EventsLost;
            [FieldOffset(96)] public uint LogBuffersLost;
            [FieldOffset(100)] public uint RealTimeBuffersLost;
            [FieldOffset(112)] public uint LogFileNameOffset;
            [FieldOffset(116)] public uint LoggerNameOffset;
        }

        [StructLayout(LayoutKind.Explicit, Size = 448, CharSet = CharSet.Unicode)]
        private struct Logfile
        {
            [FieldOffset(8), MarshalAs(UnmanagedType.LPWStr)] public string LoggerName;
            [FieldOffset(28)] public uint ProcessTraceMode;
            [FieldOffset(424)] public IntPtr EventRecordCallback;
        }

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate void EventCallback(IntPtr record);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern uint StartTraceW(out ulong session, string name, IntPtr properties);
        [DllImport("advapi32.dll", ExactSpelling = true)]
        private static extern uint EnableTraceEx2(ulong session, ref Guid provider, uint control,
            byte level, ulong anyKeyword, ulong allKeyword, uint timeout, IntPtr parameters);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern uint ControlTraceW(ulong session, string name, IntPtr properties, uint control);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern ulong OpenTraceW(ref Logfile logfile);
        [DllImport("advapi32.dll", ExactSpelling = true)]
        private static extern uint ProcessTrace([In] ulong[] handles, uint count, IntPtr start, IntPtr end);
        [DllImport("advapi32.dll", ExactSpelling = true)]
        private static extern uint CloseTrace(ulong consumer);

        private readonly string name;
        private readonly Guid provider;
        private readonly Dictionary<ushort, string> events = new Dictionary<ushort, string>();
        private readonly Dictionary<uint, string> outcomes = new Dictionary<uint, string>();
        private readonly EventCallback callback;
        private IntPtr properties;
        private ulong session;
        private bool sessionStarted;
        private ulong consumer = ulong.MaxValue;
        private Thread worker;
        private Exception consumerFailure;
        private uint processResult;
        private bool disposed;

        public OperationalTraceSession(string contractPath, string outputDirectory)
        {
            if (IntPtr.Size != 8) throw new PlatformNotSupportedException("ETW live capture requires x64");
            var records = new Dictionary<string, string>();
            foreach (string line in File.ReadAllLines(contractPath))
            {
                if (line.Length == 0) continue;
                int split = line.IndexOf('=');
                if (split <= 0) throw new InvalidDataException("Malformed trace contract record");
                records.Add(line.Substring(0, split), line.Substring(split + 1));
            }
            if (records["contract_version"] != "1") throw new InvalidDataException("Unsupported trace contract");
            provider = new Guid(records["provider_guid"]);
            foreach (var record in records)
            {
                if (record.Key.StartsWith("event_", StringComparison.Ordinal))
                    events.Add(ushort.Parse(record.Value), record.Key.Substring(6));
                if (record.Key.StartsWith("outcome_", StringComparison.Ordinal))
                    outcomes.Add(uint.Parse(record.Value), record.Key.Substring(8));
            }
            name = "ext4win-live-" + Guid.NewGuid().ToString("N");
            callback = OnEvent;
            Directory.CreateDirectory(outputDirectory);
            string filename = Path.GetFullPath(Path.Combine(outputDirectory, name + ".etl"));
            int loggerOffset = Marshal.SizeOf(typeof(Properties));
            int fileOffset = loggerOffset + (name.Length + 1) * 2;
            int size = fileOffset + (filename.Length + 1) * 2;
            properties = Marshal.AllocHGlobal(size);
            Marshal.Copy(new byte[size], 0, properties, size);
            Marshal.StructureToPtr(new Properties {
                Size = (uint)size, Guid = Guid.NewGuid(), Clock = 1, Flags = 0x20000,
                BufferSize = 16, MinimumBuffers = 4, MaximumBuffers = 16,
                MaximumFileSize = 16, LogFileMode = 0x102, FlushTimer = 1,
                LoggerNameOffset = (uint)loggerOffset, LogFileNameOffset = (uint)fileOffset
            }, properties, false);
            Marshal.Copy((name + "\0").ToCharArray(), 0, IntPtr.Add(properties, loggerOffset), name.Length + 1);
            Marshal.Copy((filename + "\0").ToCharArray(), 0, IntPtr.Add(properties, fileOffset), filename.Length + 1);
            try
            {
                Check(StartTraceW(out session, name, properties), "StartTrace");
                sessionStarted = true;
                var logfile = new Logfile {
                    LoggerName = name, ProcessTraceMode = 0x10000000 | 0x100,
                    EventRecordCallback = Marshal.GetFunctionPointerForDelegate(callback)
                };
                consumer = OpenTraceW(ref logfile);
                if (consumer == ulong.MaxValue) throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenTrace");
                worker = new Thread(Consume) { IsBackground = true, Name = name };
                worker.Start();
                Guid enabledProvider = provider;
                Check(EnableTraceEx2(session, ref enabledProvider, 1, 4, 1, 0, 0, IntPtr.Zero), "EnableTraceEx2");
                Console.WriteLine("[{0:o}] kernel ETW capture active: {1}", DateTime.UtcNow, filename);
                Console.Out.Flush();
            }
            catch
            {
                // Constructor rollback preserves the original failure and observes cleanup too.
                try { Dispose(); }
                catch (Exception cleanup) { Console.Error.WriteLine("ETW rollback failed: " + cleanup); }
                throw;
            }
        }

        private static void Check(uint status, string operation)
        {
            if (status != 0) throw new Win32Exception((int)status,
                operation + " failed with Win32 status " + status + ": " + new Win32Exception((int)status).Message);
        }

        private void Consume()
        {
            try { processResult = ProcessTrace(new[] { consumer }, 1, IntPtr.Zero, IntPtr.Zero); }
            catch (Exception failure) { Interlocked.CompareExchange(ref consumerFailure, failure, null); }
        }

        private void OnEvent(IntPtr record)
        {
            try
            {
                // EVENT_RECORD: provider at 24, descriptor.Id at 40, UserDataLength at 86,
                // UserData at 96. Only the contract's two scalar fields are ever decoded.
                Guid eventProvider = (Guid)Marshal.PtrToStructure(IntPtr.Add(record, 24), typeof(Guid));
                if (eventProvider != provider) return;
                ushort id = unchecked((ushort)Marshal.ReadInt16(record, 40));
                if (Marshal.ReadInt16(record, 86) != 8) throw new InvalidDataException("ETW scalar payload length mismatch");
                IntPtr data = Marshal.ReadIntPtr(record, 96);
                uint status = unchecked((uint)Marshal.ReadInt32(data));
                uint outcome = unchecked((uint)Marshal.ReadInt32(data, 4));
                Console.WriteLine("[{0:o}] kernel {1}: {2} NTSTATUS=0x{3:X8}",
                    DateTime.UtcNow, events[id], outcomes[outcome], status);
                Console.Out.Flush();
            }
            catch (Exception failure)
            {
                // No managed exception may cross the native callback boundary.
                if (Interlocked.CompareExchange(ref consumerFailure, failure, null) == null)
                    Console.Error.WriteLine("ETW consumer failed: " + failure);
            }
        }

        public void Dispose()
        {
            if (disposed) return;
            disposed = true;
            uint stopStatus = 0;
            uint closeStatus = 0;
            Properties final = new Properties();
            try
            {
                if (sessionStarted)
                {
                    stopStatus = ControlTraceW(session, name, properties, 1);
                    final = (Properties)Marshal.PtrToStructure(properties, typeof(Properties));
                }
                bool joined = worker == null || worker.Join(5000);
                if (consumer != ulong.MaxValue) closeStatus = CloseTrace(consumer);
                if (!joined && !worker.Join(5000))
                    throw new TimeoutException("ETW consumer did not stop; callback storage remains retained by its worker");
                Check(stopStatus, "ControlTrace stop");
                // Closing an active consumer may acknowledge asynchronous closure (7007).
                if (closeStatus != 7007) Check(closeStatus, "CloseTrace");
                if (consumerFailure != null) throw new InvalidOperationException("ETW capture failed", consumerFailure);
                if (processResult != 0 && processResult != 1223) Check(processResult, "ProcessTrace");
                if (final.EventsLost != 0 || final.LogBuffersLost != 0 || final.RealTimeBuffersLost != 0)
                    throw new InvalidDataException("ETW capture lost events or buffers");
            }
            finally
            {
                if (properties != IntPtr.Zero) Marshal.FreeHGlobal(properties);
                properties = IntPtr.Zero;
                GC.KeepAlive(callback);
            }
        }
    }
}
