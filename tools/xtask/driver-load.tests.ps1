$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.ServiceProcess
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot 'driver-load.ps1'), [ref]$tokens, [ref]$errors
)
if ($errors.Count -ne 0) { throw ($errors | Out-String) }
foreach ($name in @('Invoke-BoundedScmProcess', 'Cleanup-DriverLoadSession')) {
    $definition = $ast.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true)
    if (-not $definition) { throw "Missing function: $name" }
    . ([scriptblock]::Create($definition.Extent.Text))
}

# Exercise the actual process lifetime boundary; no SCM or driver side effects occur.
$start = [Diagnostics.ProcessStartInfo]::new()
$start.FileName = Join-Path $PSHOME 'powershell.exe'
$start.UseShellExecute = $false
$start.CreateNoWindow = $true
$start.RedirectStandardOutput = $true
$start.RedirectStandardError = $true
$start.Arguments = '-NoProfile -Command "exit 0"'
Invoke-BoundedScmProcess $start 10000
$start.Arguments = '-NoProfile -Command "exit 37"'
$failed = $false
try { Invoke-BoundedScmProcess $start 10000 }
catch [ComponentModel.Win32Exception] {
    $failed = $true
    if ($_.Exception.NativeErrorCode -ne 37) { throw 'Returned SCM error identity was lost' }
}
if (-not $failed) { throw 'Nonzero request completion was accepted' }
$start.Arguments = '-NoProfile -Command "Start-Sleep -Seconds 30"'
$timer = [Diagnostics.Stopwatch]::StartNew()
$timedOut = $false
try { Invoke-BoundedScmProcess $start 100 }
catch [TimeoutException] { $timedOut = $true }
$timer.Stop()
if (-not $timedOut -or $timer.Elapsed.TotalSeconds -gt 10) {
    throw 'An unresponsive requester did not produce a bounded uncertain outcome'
}

# Recovery must not unload or remove the image while SCM still owns initialization.
$script:State = [ordered]@{ phase = 'ServiceStartRequested'; sys_hash = 'identity' }
$serviceRegistryPath = 'HKLM:\unused-contract-test'
$serviceName = 'unused-contract-test'
function Get-InstalledSessionPackage { return @{ DriverName = 'oem-test.inf' } }
function Resolve-PackageDriverStoreSysPath { return 'identity-bound-image.sys' }
function Assert-ServiceConfiguration { }
function Get-Service { return @{ Status = [System.ServiceProcess.ServiceControllerStatus]::StartPending } }
function Write-Phase([string]$Phase) { $script:RecoveryPhase = $Phase }
function Request-BoundedDriverUnloadPreparation { throw 'Must not retire an initializing driver' }
function Invoke-Checked { throw 'Must not remove an initializing driver package' }
$refused = $false
try { Cleanup-DriverLoadSession }
catch {
    if ($_.Exception.Message -notmatch 'initialization remains StartPending') { throw }
    $refused = $true
}
if (-not $refused -or $script:RecoveryPhase -ne 'CleanupServiceStartPending') {
    throw 'Recovery did not preserve the unresolved initialization boundary'
}
Write-Output 'driver-load harness contracts: PASS'
