param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Preflight', 'Run', 'Cleanup')]
    [string]$Mode,

    [Parameter(Mandatory = $true)]
    [string]$RepositoryRoot,

    [string]$Bundle,

    [string]$BundleArtifactId,

    [string]$BundleSysHash,

    [string]$BundleCatalogHash,

    [string]$BundleInfHash,

    [string]$SessionId
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$sessionParent = Join-Path $RepositoryRoot 'target\live-vhdx-sessions'
$driverSessionParent = Join-Path $RepositoryRoot 'target\driver-load-sessions'
$driverLoadScript = Join-Path $RepositoryRoot 'tools\xtask\driver-load.ps1'
$script:State = [ordered]@{}
$script:SessionDirectory = $null

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'live VHDX validation requires an elevated administrator process'
    }
}

function Assert-SessionId([string]$Value) {
    if ($Value -notmatch '^[0-9a-f]{32}$') {
        throw 'session id must be exactly 32 lowercase hexadecimal digits'
    }
}

function Invoke-Checked([string]$Program, [string[]]$Arguments, [string]$Description) {
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE"
    }
}

function Invoke-Wsl([string[]]$Arguments, [string]$Description) {
    $output = @(& wsl.exe @Arguments)
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE"
    }
    return $output
}

function Invoke-DriverLoadSession([string]$RequestedMode, [string]$RequestedSessionId, [string[]]$BundleArguments) {
    if (-not (Test-Path -LiteralPath $driverLoadScript -PathType Leaf)) {
        throw 'repository driver-load workflow script is absent'
    }
    $arguments = @(
        '-NoLogo',
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy',
        'Bypass',
        '-File',
        $driverLoadScript,
        '-Mode',
        $RequestedMode,
        '-RepositoryRoot',
        $RepositoryRoot,
        '-SessionId',
        $RequestedSessionId
    )
    if ($BundleArguments) {
        $arguments += $BundleArguments
    }
    Invoke-Checked 'powershell.exe' $arguments "delegated driver-load $RequestedMode session"
}

function Assert-VerifierConfiguration {
    $settingsPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
    $settings = Get-ItemProperty -LiteralPath $settingsPath -ErrorAction Stop
    $level = [uint32]$settings.VerifyDriverLevel
    $drivers = @(([string]$settings.VerifyDrivers) -split '[,;\s]+' | Where-Object { $_ })
    if ($level -eq 0 -or -not ($drivers -contains 'ext4win.sys')) {
        throw 'Driver Verifier must have nonzero flags and explicitly include ext4win.sys'
    }
}

function Assert-HostContract {
    Assert-Administrator
    foreach ($command in @('New-VHD', 'Get-VHD', 'Mount-VHD', 'Dismount-VHD', 'Get-Disk', 'Initialize-Disk', 'New-Partition')) {
        if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
            throw "Hyper-V PowerShell command is unavailable: $command"
        }
    }
    foreach ($program in @('wsl.exe', 'fsutil.exe')) {
        if (-not (Get-Command $program -ErrorAction SilentlyContinue)) {
            throw "required Windows command is unavailable: $program"
        }
    }
    Invoke-Wsl @('--status') 'WSL status query' | Out-Null
    Invoke-Wsl @('--exec', 'mke2fs', '-V') 'WSL e2fsprogs query' | Out-Null
    Assert-VerifierConfiguration
}

function Read-KeyValueFile([string]$Path) {
    $values = [ordered]@{}
    foreach ($line in [IO.File]::ReadAllLines($Path)) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }
        $separator = $line.IndexOf('=')
        if ($separator -le 0) {
            throw "invalid manifest record in $Path"
        }
        $key = $line.Substring(0, $separator)
        $value = $line.Substring($separator + 1)
        if ($values.Contains($key)) {
            throw "duplicate manifest key $key in $Path"
        }
        $values[$key] = $value
    }
    return $values
}

function Set-StateValue([string]$Name, [string]$Value) {
    if ($Name.Contains('=') -or $Name.Contains("`n") -or $Value.Contains("`r") -or $Value.Contains("`n")) {
        throw 'session manifest keys and values must be single-line records'
    }
    $script:State[$Name] = $Value
}

function Write-Phase([string]$Phase) {
    if (-not ('Ext4Win.LivePhasePublication' -as [type])) {
        Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
namespace Ext4Win {
    public static class LivePhasePublication {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool MoveFileEx(string source, string destination, uint flags);
    }
}
'@
    }
    $sequence = 0
    if ($script:State.Contains('phase_sequence')) {
        $sequence = [int]$script:State.phase_sequence + 1
    }
    Set-StateValue 'phase_sequence' ([string]$sequence)
    Set-StateValue 'phase' $Phase
    $path = Join-Path $script:SessionDirectory ('session-v1-{0:D4}.manifest' -f $sequence)
    $pendingPath = "$path-$([Guid]::NewGuid().ToString('N')).pending"
    $stream = [IO.File]::Open($pendingPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try {
        $writer = [IO.StreamWriter]::new($stream, [Text.UTF8Encoding]::new($false), 4096, $true)
        try {
            foreach ($key in ($script:State.Keys | Sort-Object)) {
                $writer.WriteLine('{0}={1}', $key, $script:State[$key])
            }
            $writer.Flush()
            $stream.Flush($true)
        }
        finally {
            $writer.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
    # Recovery reads only published records. Flush both contents and filename publication before
    # the next VHDX effect, without replacing a previously acknowledged sequence number.
    if (-not [Ext4Win.LivePhasePublication]::MoveFileEx($pendingPath, $path, 8)) {
        $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw [ComponentModel.Win32Exception]::new($errorCode, 'durable live phase publication failed')
    }
}

function Load-Session([string]$RequestedSessionId) {
    Assert-SessionId $RequestedSessionId
    $parent = (Resolve-Path -LiteralPath $sessionParent).Path
    $candidate = Join-Path $parent $RequestedSessionId
    $resolved = (Resolve-Path -LiteralPath $candidate).Path
    if ((Split-Path -Parent $resolved) -ne $parent -or (Split-Path -Leaf $resolved) -ne $RequestedSessionId) {
        throw 'session path escaped the live VHDX session root'
    }
    $latest = Get-ChildItem -LiteralPath $resolved -Filter 'session-v1-*.manifest' -File | Sort-Object Name | Select-Object -Last 1
    if (-not $latest) {
        throw 'session has no durable manifest'
    }
    $script:SessionDirectory = $resolved
    $script:State = Read-KeyValueFile $latest.FullName
    if ($script:State.manifest_version -ne '1' -or $script:State.session_id -ne $RequestedSessionId) {
        throw 'session manifest identity mismatch'
    }
    $expectedVhdx = Join-Path $resolved 'disk.vhdx'
    if ($script:State.vhdx_path -ne $expectedVhdx) {
        throw 'session VHDX path does not match its generated identity boundary'
    }
    if ($script:State.driver_session_id -ne $RequestedSessionId) {
        throw 'live VHDX session does not identify its delegated driver-load session'
    }
}

function Get-SessionDisk {
    $vhdxPath = $script:State.vhdx_path
    $vhd = Get-VHD -Path $vhdxPath -ErrorAction SilentlyContinue
    if (-not $vhd -or -not $vhd.Attached) {
        return $null
    }
    $disk = @(Get-Disk -Number $vhd.DiskNumber)
    if ($disk.Count -ne 1) {
        throw 'attached session VHDX did not resolve to exactly one disk'
    }
    if ($script:State.Contains('disk_unique_id') -and $script:State.disk_unique_id -ne [string]$disk[0].UniqueId) {
        throw 'attached disk unique ID differs from the session manifest'
    }
    return $disk[0]
}

function Format-SessionVhdx {
    $before = @(Invoke-Wsl @('--exec', 'lsblk', '-dn', '-o', 'NAME') 'WSL device inventory before VHDX attach')
    Set-StateValue 'wsl_attached' 'true'
    Write-Phase 'WslAttachRequested'
    Invoke-Wsl @('--mount', '--vhd', $script:State.vhdx_path, '--bare') 'WSL VHDX attach' | Out-Null
    Write-Phase 'WslAttached'
    $after = @(Invoke-Wsl @('--exec', 'lsblk', '-dn', '-o', 'NAME') 'WSL device inventory after VHDX attach')
    $newDevices = @($after | Where-Object { $_ -and $_ -notin $before })
    if ($newDevices.Count -ne 1 -or $newDevices[0] -notmatch '^[A-Za-z0-9]+$') {
        throw 'WSL attach did not expose exactly one safely named block device'
    }
    Set-StateValue 'wsl_device' ([string]$newDevices[0])
    $layout = @(Invoke-Wsl @('--exec', 'lsblk', '-ln', '-o', 'NAME,TYPE', "/dev/$($newDevices[0])") 'WSL partition inventory')
    $partitions = @($layout | ForEach-Object {
        $fields = $_ -split '\s+'
        if ($fields.Count -eq 2 -and $fields[1] -eq 'part' -and $fields[0] -match '^[A-Za-z0-9]+$') {
            $fields[0]
        }
    })
    if ($partitions.Count -ne 1) {
        throw 'session VHDX did not expose exactly one WSL partition'
    }
    Set-StateValue 'wsl_partition' ([string]$partitions[0])
    Write-Phase 'WslFormatRequested'
    Invoke-Wsl @('--user', 'root', '--exec', 'mke2fs', '-t', 'ext4', '-F', '-b', '4096', '-O', 'metadata_csum,64bit', "/dev/$($partitions[0])") 'WSL ext4 format' | Out-Null
    Write-Phase 'WslFormatted'
    Write-Phase 'WslUnmountRequested'
    Invoke-Wsl @('--unmount', $script:State.vhdx_path) 'WSL VHDX unmount' | Out-Null
    Set-StateValue 'wsl_attached' 'false'
    Write-Phase 'WslUnmounted'
}

function Exercise-SessionVolume([string[]]$BundleArguments) {
    Write-Phase 'WindowsAttachRequested'
    $vhd = Mount-VHD -Path $script:State.vhdx_path -Passthru
    $disk = @($vhd | Get-Disk)
    if ($disk.Count -ne 1 -or [string]$disk[0].UniqueId -ne $script:State.disk_unique_id) {
        throw 'Windows reattach selected a disk outside the session identity'
    }
    Write-Phase 'WindowsAttached'
    Write-Phase 'DriverLoadSessionStartRequested'
    Invoke-DriverLoadSession 'Start' $script:State.driver_session_id $BundleArguments
    Set-StateValue 'driver_session_started' 'true'
    Write-Phase 'DriverLoadSessionStarted'
    $partition = @(Get-Partition -DiskNumber $disk[0].Number | Where-Object { $_.Type -ne 'Reserved' })
    if ($partition.Count -ne 1 -or [string]$partition[0].PartitionNumber -ne $script:State.partition_number) {
        throw 'session partition identity changed after WSL formatting'
    }
    Write-Phase 'AccessPathRequested'
    $partition[0] | Add-PartitionAccessPath -AssignDriveLetter
    $mounted = Get-Partition -DiskNumber $disk[0].Number -PartitionNumber $partition[0].PartitionNumber
    if (-not $mounted.DriveLetter) {
        throw 'Windows did not assign an access path to the ext4 session volume'
    }
    Set-StateValue 'drive_letter' ([string]$mounted.DriveLetter)
    Write-Phase 'AccessPathAssigned'
    $root = '{0}:\' -f $mounted.DriveLetter
    $alpha = Join-Path $root 'alpha.bin'
    $beta = Join-Path $root 'beta.bin'
    $hardlink = Join-Path $root 'beta-link.bin'
    $payload = [byte[]]::new(8192)
    for ($index = 0; $index -lt $payload.Length; $index++) {
        $payload[$index] = [byte]($index % 251)
    }
    Write-Phase 'FilesystemOperationsRequested'
    [IO.File]::WriteAllBytes($alpha, $payload)
    $readback = [IO.File]::ReadAllBytes($alpha)
    if ([Convert]::ToBase64String($payload) -ne [Convert]::ToBase64String($readback)) {
        throw 'live VHDX readback differed from the written payload'
    }
    Move-Item -LiteralPath $alpha -Destination $beta
    New-Item -ItemType HardLink -Path $hardlink -Target $beta | Out-Null
    $matches = @([IO.Directory]::EnumerateFiles($root, 'beta*'))
    if ($matches.Count -ne 2) {
        throw 'patterned directory enumeration did not return both hard-link names'
    }
    $stream = [IO.FileStream]::new($beta, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::Read, 4096, [IO.FileOptions]::WriteThrough)
    try {
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
    Write-Phase 'FilesystemOperationsCompleted'
    Write-Phase 'VolumeDismountRequested'
    Invoke-Checked 'fsutil.exe' @('volume', 'dismount', ('{0}:' -f $mounted.DriveLetter)) 'ext4 session volume dismount'
    Remove-PartitionAccessPath -DiskNumber $disk[0].Number -PartitionNumber $partition[0].PartitionNumber -AccessPath $root
    Set-StateValue 'drive_letter' ''
    Dismount-VHD -Path $script:State.vhdx_path
    Write-Phase 'VolumeDismounted'
}

function Cleanup-VhdxResources {
    if ($script:State.wsl_attached -eq 'true') {
        Write-Phase 'CleanupWslUnmountRequested'
        Invoke-Wsl @('--unmount', $script:State.vhdx_path) 'cleanup WSL VHDX unmount' | Out-Null
        Set-StateValue 'wsl_attached' 'false'
        Write-Phase 'CleanupWslUnmounted'
    }
    $disk = Get-SessionDisk
    if ($disk) {
        Write-Phase 'CleanupVhdxDismountRequested'
        Dismount-VHD -Path $script:State.vhdx_path
        Write-Phase 'CleanupVhdxDismounted'
    }
    if (Test-Path -LiteralPath $script:State.vhdx_path) {
        $expectedVhdx = Join-Path $script:SessionDirectory 'disk.vhdx'
        if ($script:State.vhdx_path -ne $expectedVhdx) {
            throw 'cleanup refused a VHDX outside the session directory'
        }
        Write-Phase 'CleanupVhdxRemovalRequested'
        Remove-Item -LiteralPath $script:State.vhdx_path -Force
        Write-Phase 'CleanupVhdxRemoved'
    }
    if (Test-Path -LiteralPath $script:State.vhdx_path) {
        throw 'session VHDX remains after cleanup'
    }
}

function Cleanup-DriverLoadResources {
    $driverSessionDirectory = Join-Path $driverSessionParent $script:State.driver_session_id
    if (Test-Path -LiteralPath $driverSessionDirectory -PathType Container) {
        Write-Phase 'CleanupDriverLoadSessionRequested'
        Invoke-DriverLoadSession 'Cleanup' $script:State.driver_session_id @()
        Set-StateValue 'driver_session_started' 'false'
        Write-Phase 'CleanupDriverLoadSessionCompleted'
    }
    elseif ($script:State.driver_session_started -eq 'true') {
        throw 'live VHDX session reports a started driver-load session but its durable identity is absent'
    }
}

function Cleanup-SessionInternal {
    $vhdxCleanupError = $null
    try {
        Cleanup-VhdxResources
    }
    catch {
        $vhdxCleanupError = $_
    }

    $driverCleanupError = $null
    try {
        Cleanup-DriverLoadResources
    }
    catch {
        $driverCleanupError = $_
    }

    if ($vhdxCleanupError -and $driverCleanupError) {
        throw "VHDX cleanup failed ($vhdxCleanupError); mandatory driver-load cleanup also failed ($driverCleanupError)"
    }
    if ($vhdxCleanupError) {
        throw $vhdxCleanupError
    }
    if ($driverCleanupError) {
        throw $driverCleanupError
    }
    Write-Phase 'Complete'
}

function Start-LiveSession([string[]]$BundleArguments, [string]$RequestedSessionId) {
    Assert-HostContract
    Assert-SessionId $RequestedSessionId
    New-Item -ItemType Directory -Path $sessionParent -Force | Out-Null
    $script:SessionDirectory = Join-Path $sessionParent $RequestedSessionId
    New-Item -ItemType Directory -Path $script:SessionDirectory | Out-Null
    $vhdxPath = Join-Path $script:SessionDirectory 'disk.vhdx'
    Set-StateValue 'manifest_version' '1'
    Set-StateValue 'session_id' $RequestedSessionId
    Set-StateValue 'driver_session_id' $RequestedSessionId
    Set-StateValue 'vhdx_path' $vhdxPath
    Set-StateValue 'wsl_attached' 'false'
    Set-StateValue 'driver_session_started' 'false'
    Write-Phase 'SessionCreated'

    $operationError = $null
    try {
        Write-Phase 'VhdxCreateRequested'
        New-VHD -Path $vhdxPath -Fixed -SizeBytes 268435456 | Out-Null
        Write-Phase 'VhdxCreated'
        Write-Phase 'PartitioningAttachRequested'
        $vhd = Mount-VHD -Path $vhdxPath -Passthru
        $disk = @($vhd | Get-Disk)
        if ($disk.Count -ne 1) {
            throw 'new session VHDX did not resolve to exactly one disk'
        }
        Set-StateValue 'disk_unique_id' ([string]$disk[0].UniqueId)
        Write-Phase 'PartitioningAttached'
        Write-Phase 'PartitionCreateRequested'
        Set-Disk -Number $disk[0].Number -IsOffline $false -IsReadOnly $false
        Initialize-Disk -Number $disk[0].Number -PartitionStyle GPT
        $partition = New-Partition -DiskNumber $disk[0].Number -UseMaximumSize
        Set-StateValue 'partition_number' ([string]$partition.PartitionNumber)
        Write-Phase 'PartitionCreated'
        Write-Phase 'PartitioningDismountRequested'
        Dismount-VHD -Path $vhdxPath
        Write-Phase 'PartitioningDismounted'
        Format-SessionVhdx
        Exercise-SessionVolume $BundleArguments
    }
    catch {
        $operationError = $_
    }

    $cleanupError = $null
    try {
        Cleanup-SessionInternal
    }
    catch {
        $cleanupError = $_
    }
    if ($operationError -and $cleanupError) {
        throw "live operation failed ($operationError); mandatory cleanup also failed ($cleanupError)"
    }
    if ($operationError) {
        throw $operationError
    }
    if ($cleanupError) {
        throw $cleanupError
    }
}

switch ($Mode) {
    'Preflight' {
        Assert-HostContract
        Write-Output 'live VHDX host contract: PASS'
    }
    'Run' {
        if (-not $Bundle -or -not $BundleArtifactId -or -not $BundleSysHash -or
            -not $BundleCatalogHash -or -not $BundleInfHash -or -not $SessionId) {
            throw 'Run requires generated production bundle identity and SessionId arguments'
        }
        # Forward the Rust-verified identity without parsing or independently interpreting it.
        # Only the driver-load owner validates this boundary and persists package identity.
        $bundleArguments = @(
            '-Bundle', $Bundle,
            '-BundleArtifactId', $BundleArtifactId,
            '-BundleSysHash', $BundleSysHash,
            '-BundleCatalogHash', $BundleCatalogHash,
            '-BundleInfHash', $BundleInfHash
        )
        Start-LiveSession $bundleArguments $SessionId
    }
    'Cleanup' {
        Assert-Administrator
        if (-not $SessionId) {
            throw 'Cleanup requires a generated SessionId argument'
        }
        Load-Session $SessionId
        if ($script:State.phase -eq 'Complete') {
            Write-Output 'live VHDX session is already complete'
            break
        }
        Cleanup-SessionInternal
    }
}
