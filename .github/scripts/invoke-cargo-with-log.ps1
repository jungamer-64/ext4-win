param(
    [Parameter(Mandatory)]
    [string] $LogPath,

    [Parameter(Mandatory)]
    [string[]] $CargoArguments
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

& cargo @CargoArguments 2>&1 |
    ForEach-Object { $_.ToString() } |
    Tee-Object -LiteralPath $LogPath
exit $LASTEXITCODE
