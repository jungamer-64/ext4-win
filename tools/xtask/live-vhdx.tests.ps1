$ErrorActionPreference = 'Stop'

# Load only the functions under test. Evaluating the script's dispatch would
# require elevation and could create storage; these tests exercise report boundaries.
$tokens = $null
$errors = $null
$source = Join-Path $PSScriptRoot 'live-vhdx.ps1'
$ast = [Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) { throw ($errors | Out-String) }
foreach ($name in @('Read-VerifierActivity', 'Assert-LoadedDriverVerifier', 'Start-VerifiedDriverSession', 'Invoke-Wsl', 'Dismount-SessionFilesystemForCleanup', 'Resolve-WslSessionPartition')) {
    $definition = $ast.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true)
    if (-not $definition) { throw "Missing function: $name" }
    . ([scriptblock]::Create($definition.Extent.Text))
}

$partitionId = [Guid]'2ca3ad84-858a-49ba-be4a-430713ddf498'
$partitionType = [Guid]'0fc63daf-8483-4772-8e79-3d69d8477de4'
$layout = @(
    'sde disk',
    'sde1 part 98740d78-04a2-4e2d-8ac4-4cf186293890 e3c9e316-0b5c-4db8-817d-f92df00215ae',
    'sde2 part 2ca3ad84-858a-49ba-be4a-430713ddf498 0fc63daf-8483-4772-8e79-3d69d8477de4'
)
if ((Resolve-WslSessionPartition $layout $partitionId $partitionType) -cne 'sde2') {
    throw 'WSL partition selection ignored the recorded GPT identity'
}
foreach ($invalid in @(
    @($layout[0], $layout[1]),
    @($layout[0], $layout[1], $layout[2].Replace('2ca3ad84', '2ca3ad85')),
    @($layout[0], $layout[1], $layout[2].Replace('0fc63daf', '0fc63dae')),
    @($layout[0], $layout[1], $layout[2], $layout[2].Replace('sde2', 'sde3'))
)) {
    $rejected = $false
    try { Resolve-WslSessionPartition $invalid $partitionId $partitionType | Out-Null }
    catch { $rejected = $true }
    if (-not $rejected) { throw 'WSL partition selection accepted an absent or ambiguous GPT identity' }
}

$active = "Verifier Flags: 0x001209bb`nMODULE: ext4win.sys (load: 1 / unload: 0)"
$activity = Read-VerifierActivity $active
if ($activity.Flags -ne 0x001209bb -or $activity.Loads -ne 1 -or $activity.Unloads -ne 0) {
    throw 'Runtime Verifier counters were not preserved'
}
$neverLoaded = "Verifier Flags: 0x0002091b`nMODULE: ext4win.sys (load: 0 / unload: 0)"
Read-VerifierActivity $neverLoaded | Out-Null

foreach ($invalid in @(
    '',
    'VerifyDrivers=ext4win.sys',
    $active.Replace('0x001209bb', '0x00000000'),
    $active.Replace('0x001209bb', '0x00000001'),
    $active.Replace('ext4win.sys', 'other.sys'),
    $active.Replace('ext4win.sys', 'ext4win.sys.bak'),
    "$active`nMODULE: ext4win.sys (load: 1 / unload: 0)",
    $active.Replace('load: 1', 'load: unknown')
)) {
    $rejected = $false
    try { Read-VerifierActivity $invalid | Out-Null }
    catch { $rejected = $true }
    if (-not $rejected) { throw "Invalid runtime report accepted: $invalid" }
}

# Model the native command boundary without running verifier or publishing phases.
function Invoke-Checked { return $script:Report }
function Write-Phase([string]$Phase) { $script:PublishedPhase = $Phase }
$script:SessionDirectory = Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $script:SessionDirectory | Out-Null
try {
    foreach ($report in @($neverLoaded, $active.Replace('unload: 0', 'unload: 1'))) {
        $script:Report = $report
        $script:PublishedPhase = $null
        $rejected = $false
        try { Assert-LoadedDriverVerifier }
        catch { $rejected = $true }
        if (-not $rejected -or $script:PublishedPhase) {
            throw 'A driver that is not loaded passed live Verifier acceptance'
        }
    }
    $script:Report = $active
    Assert-LoadedDriverVerifier
    if ($script:PublishedPhase -ne 'LoadedDriverVerifierConfirmed') {
        throw 'A loaded, verified driver did not publish acceptance'
    }
}
finally {
    Remove-Item -LiteralPath (Join-Path $script:SessionDirectory 'verifier-runtime.txt') -ErrorAction SilentlyContinue
    [IO.Directory]::Delete($script:SessionDirectory, $false)
}

function wsl.exe {
    $script:WslArguments = @($args)
    $global:LASTEXITCODE = $script:WslExitCode
    return 'oracle output'
}
$script:WslExitCode = 0
Invoke-Wsl @('--exec', 'mke2fs', '-V') 'oracle query' | Out-Null
$expected = @('--user', 'root', '--exec', '/usr/bin/env',
    'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'mke2fs', '-V')
if (($script:WslArguments -join '|') -cne ($expected -join '|')) {
    throw 'WSL execution did not establish root and the oracle PATH'
}
Invoke-Wsl @('--unmount', 'C:\session with spaces\disk.vhdx') 'detach' | Out-Null
if (($script:WslArguments -join '|') -cne '--unmount|C:\session with spaces\disk.vhdx') {
    throw 'WSL host arguments changed at the execution boundary'
}
$script:WslExitCode = 1
$rejected = $false
try { Invoke-Wsl @('--shutdown') 'shutdown' | Out-Null }
catch { $rejected = $true }
if (-not $rejected) { throw 'WSL failure was ignored' }
$global:LASTEXITCODE = 0

# The running driver must exist before immediate DIF activation, and the
# runtime report must be accepted before the filesystem scenario can proceed.
$script:State = @{ driver_session_id = '0123456789abcdef0123456789abcdef' }
$script:StartEvents = [Collections.Generic.List[string]]::new()
$script:ActivationFails = $false
function Write-Phase([string]$Phase) { $script:StartEvents.Add("phase:$Phase") }
function Set-StateValue([string]$Name, [string]$Value) { $script:State[$Name] = $Value }
function Invoke-DriverLoadSession([string]$Mode, [string]$SessionId, [string[]]$BundleArguments) {
    if ($Mode -cne 'Start' -or $SessionId -cne $script:State.driver_session_id -or
        ($BundleArguments -join '|') -cne 'bundle') {
        throw 'Driver-load identity was not forwarded intact'
    }
    $script:StartEvents.Add('driver-started')
}
function Invoke-Checked([string]$Program, [string[]]$Arguments, [string]$Description) {
    if ($Program -cne 'verifier.exe' -or
        ($Arguments -join '|') -cne '/dif|1|2|4|5|9|12|18|/now|/driver|ext4win.sys') {
        throw 'Immediate Driver Verifier command was not scoped to ext4win.sys'
    }
    $script:StartEvents.Add('verifier-activation')
    if ($script:ActivationFails) { throw 'activation failed' }
}
function Assert-LoadedDriverVerifier { $script:StartEvents.Add('runtime-confirmed') }

Start-VerifiedDriverSession @('bundle')
$expectedStart = @(
    'phase:DriverLoadSessionStartRequested',
    'driver-started',
    'phase:DriverLoadSessionStarted',
    'phase:DriverVerifierActivationRequested',
    'verifier-activation',
    'runtime-confirmed'
)
if (($script:StartEvents -join '|') -cne ($expectedStart -join '|') -or
    $script:State.driver_session_started -cne 'true') {
    throw 'Driver startup, immediate Verifier activation, and runtime confirmation were not ordered'
}
$script:StartEvents.Clear()
$script:ActivationFails = $true
$rejected = $false
try { Start-VerifiedDriverSession @('bundle') }
catch { $rejected = $true }
if (-not $rejected -or $script:StartEvents.Contains('runtime-confirmed')) {
    throw 'Failed Verifier activation proceeded to filesystem acceptance'
}

# A failed partition creation may leave a session VHDX attached, but there is
# no filesystem to dismount until its identity has been published durably.
$script:State = @{ driver_session_id = '0123456789abcdef0123456789abcdef'; driver_session_started = 'false' }
$driverSessionParent = Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString('N'))
$script:StartEvents.Clear()
function Get-SessionPartition { throw 'partition lookup must not run before identity publication' }
Dismount-SessionFilesystemForCleanup
if (($script:StartEvents -join '|') -cne 'phase:CleanupPartitionUnrecorded') {
    throw 'Unrecorded partition cleanup did not preserve the early lifecycle boundary'
}
$script:State.driver_session_started = 'true'
$rejected = $false
try { Dismount-SessionFilesystemForCleanup }
catch { $rejected = $true }
if (-not $rejected) {
    throw 'Cleanup accepted an unrecorded partition after driver startup'
}

Write-Output 'live VHDX harness contracts: PASS'
