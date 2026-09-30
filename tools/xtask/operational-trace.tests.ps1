$ErrorActionPreference = 'Stop'

# This exercises the actual ETW ABI, enable-before-registration, realtime delivery,
# scalar decoding and joined shutdown without installing or loading any driver.
Add-Type -Path (Join-Path $PSScriptRoot 'operational-trace.cs')
$testDirectory = Join-Path ([IO.Path]::GetTempPath()) ('ext4win-etw-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testDirectory | Out-Null
$provider = [Guid]::NewGuid().ToString()
$contract = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../../crates/ext4-driver/operational-trace-v1.txt') -Raw
$contract = $contract -replace '(?m)^provider_guid=.*$', "provider_guid=$provider"
$contractPath = Join-Path $testDirectory 'trace.txt'
[IO.File]::WriteAllText($contractPath, $contract)
Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public sealed class ScalarTraceSource : IDisposable
{
    [StructLayout(LayoutKind.Sequential)]
    private struct Descriptor
    {
        public ushort Id;
        public byte Version, Channel, Level, Opcode;
        public ushort Task;
        public ulong Keyword;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct Data
    {
        public ulong Pointer;
        public uint Size, Reserved;
    }
    [DllImport("advapi32.dll", ExactSpelling = true)]
    private static extern uint EventRegister(ref Guid provider, IntPtr callback, IntPtr context, out ulong handle);
    [DllImport("advapi32.dll", ExactSpelling = true)]
    private static extern uint EventWrite(ulong handle, ref Descriptor descriptor, uint count, ref Data data);
    [DllImport("advapi32.dll", ExactSpelling = true)]
    private static extern uint EventUnregister(ulong handle);
    private ulong registration;
    public ScalarTraceSource()
    {
        Guid id = new Guid("$provider");
        Check(EventRegister(ref id, IntPtr.Zero, IntPtr.Zero, out registration));
    }
    private static void Check(uint status)
    {
        if (status != 0) throw new Win32Exception((int)status);
    }
    public void DriverInitialization(int status, uint outcome)
    {
        IntPtr payload = Marshal.AllocHGlobal(8);
        try
        {
            Marshal.WriteInt32(payload, status);
            Marshal.WriteInt32(payload, 4, unchecked((int)outcome));
            var data = new Data { Pointer = unchecked((ulong)payload.ToInt64()), Size = 8 };
            var descriptor = new Descriptor { Id = 18, Level = 4, Keyword = 1 };
            Check(EventWrite(registration, ref descriptor, 1, ref data));
        }
        finally { Marshal.FreeHGlobal(payload); }
    }
    public void Dispose()
    {
        if (registration != 0) Check(EventUnregister(registration));
        registration = 0;
    }
}
"@
$capture = $null
$source = $null
$originalOutput = [Console]::Out
$text = [IO.StringWriter]::new()
$output = [IO.TextWriter]::Synchronized($text)
try {
    [Console]::SetOut($output)
    $capture = [Ext4Win.OperationalTraceSession]::new($contractPath, $testDirectory)
    # Registration happens after EnableTraceEx2, as with a demand-loaded kernel provider.
    $source = [ScalarTraceSource]::new()
    $source.DriverInitialization(0, 1)
    $source.DriverInitialization(-1073741811, 4) # STATUS_INVALID_PARAMETER
    $source.DriverInitialization(0, 2)
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    do {
        Start-Sleep -Milliseconds 50
        [Threading.Monitor]::Enter($output)
        try { $observed = $text.ToString() }
        finally { [Threading.Monitor]::Exit($output) }
    } while ($observed -notmatch 'driver_initialization: completed' -and [DateTime]::UtcNow -lt $deadline)
    $source.Dispose()
    $source = $null
    $capture.Dispose()
    $capture = $null
    $observed = $text.ToString()
    foreach ($expected in @(
        'driver_initialization: selected NTSTATUS=0x00000000',
        'driver_initialization: failed NTSTATUS=0xC000000D',
        'driver_initialization: completed NTSTATUS=0x00000000'
    )) {
        if (-not $observed.Contains($expected)) { throw "ETW observation missing: $expected`n$observed" }
    }
    if (@(Get-ChildItem -LiteralPath $testDirectory -Filter '*.etl').Count -ne 1) {
        throw 'ETW session did not persist its trace artifact'
    }
}
finally {
    try {
        if ($source) { $source.Dispose() }
        if ($capture) { $capture.Dispose() }
    }
    finally {
        [Console]::SetOut($originalOutput)
        $output.Dispose()
        # All files here belong to this generated directory; never recurse into arbitrary paths.
        foreach ($file in Get-ChildItem -LiteralPath $testDirectory -File) {
            Remove-Item -LiteralPath $file.FullName
        }
        [IO.Directory]::Delete($testDirectory, $false)
    }
}
Write-Output 'operational ETW contracts: PASS'
