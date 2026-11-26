[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [guid] $VmId,

    [Parameter(Mandatory)]
    [ValidatePattern('\A[0-9a-f]{32}\z', Options = 'None')]
    [string] $SessionId,

    [Parameter(Mandatory)]
    [string] $EvidenceRoot
)

$ErrorActionPreference = 'Stop'
$machine = Get-VM -Id $VmId
$port = Get-VMComPort -VM $machine -Number 1
if ($port.Path -cnotmatch '\A\\\\\.\\pipe\\[A-Za-z0-9._-]+\z') {
    throw 'The target VM must expose COM1 through a local Hyper-V named pipe.'
}

$root = Get-Item -LiteralPath $EvidenceRoot
if ($root.PSProvider.Name -ne 'FileSystem' -or -not $root.PSIsContainer) {
    throw 'EvidenceRoot must be an existing host filesystem directory.'
}
$debugger = Get-Command kd.exe -CommandType Application
$session = New-Item -Path (Join-Path $root.FullName $SessionId) -ItemType Directory
$log = Join-Path $session.FullName 'kernel.log'
Write-Host "VM $VmId, session $SessionId. KD log $log"
& $debugger.Path -noshell -logo $log -k "com:pipe,port=$($port.Path),resets=0,reconnect"
if ($LASTEXITCODE -ne 0) {
    throw "Kernel debugger exited with code $LASTEXITCODE."
}
