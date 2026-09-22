$ErrorActionPreference = 'Stop'

# Load only the functions under test. Evaluating the script's dispatch would
# require elevation and could create storage; these tests exercise report boundaries.
$tokens = $null
$errors = $null
$source = Join-Path $PSScriptRoot 'live-vhdx.ps1'
$ast = [Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) { throw ($errors | Out-String) }
foreach ($name in @('Read-VerifierActivity', 'Assert-LoadedDriverVerifier', 'Invoke-Wsl')) {
    $definition = $ast.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true)
    if (-not $definition) { throw "Missing function: $name" }
    . ([scriptblock]::Create($definition.Extent.Text))
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
Write-Output 'live VHDX harness contracts: PASS'
