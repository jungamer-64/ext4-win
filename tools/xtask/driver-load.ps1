param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Preflight', 'Start', 'Run', 'Cleanup')]
    [string]$Mode,

    [Parameter(Mandatory = $true)]
    [string]$RepositoryRoot,

    [string]$Bundle,

    [string]$SessionId
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$serviceName = 'ext4win'
$originalInf = 'ext4win.inf'
$providerName = 'ext4-win'
$sessionParent = Join-Path $RepositoryRoot 'target\driver-load-sessions'
$serviceRegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\ext4win'
$script:State = [ordered]@{}
$script:SessionDirectory = $null
$script:SessionEstablished = $false

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'driver-load validation requires an elevated administrator process'
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

function Get-Sha256FileHash([string]$Path) {
    $stream = [IO.File]::Open(
        $Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    try {
        $sha256 = [Security.Cryptography.SHA256]::Create()
        try {
            $digest = $sha256.ComputeHash($stream)
        }
        finally {
            $sha256.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
    return [BitConverter]::ToString($digest).Replace('-', '')
}

function Get-Ext4WinPackages([string]$InventoryPath) {
    Invoke-Checked 'pnputil.exe' @('/enum-drivers', '/files', '/format', 'xml', '/output-file', $InventoryPath) 'structured DriverStore inventory' | Out-Null
    [xml]$inventory = [IO.File]::ReadAllText($InventoryPath)
    return @($inventory.PnpUtil.Driver | Where-Object {
        [string]$_.OriginalName -ieq $originalInf -and [string]$_.ProviderName -ieq $providerName
    })
}

function Assert-TestSigning {
    $output = @(& bcdedit.exe /enum '{current}' 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "BCD current-loader query failed with exit code $LASTEXITCODE"
    }
    $output | ForEach-Object { Write-Output $_ }
    $enabled = @($output | Where-Object { [string]$_ -match '^\s*testsigning\s+(Yes|On)\s*$' })
    if ($enabled.Count -ne 1) {
        throw 'the current boot loader does not report TESTSIGNING enabled'
    }
}

function Assert-CleanDriverState {
    if ((Test-Path -LiteralPath $serviceRegistryPath) -or (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) {
        throw 'an ext4win service already exists; driver-load validation requires a clean host'
    }
    $inventoryPath = Join-Path ([IO.Path]::GetTempPath()) ("ext4win-inventory-{0}.xml" -f [Guid]::NewGuid().ToString('N'))
    try {
        if (@(Get-Ext4WinPackages $inventoryPath).Count -ne 0) {
            throw 'one or more ext4win DriverStore packages already exist; recover or clean the host first'
        }
    }
    finally {
        if (Test-Path -LiteralPath $inventoryPath) {
            Remove-Item -LiteralPath $inventoryPath -Force
        }
    }
}

function Assert-HostContract([bool]$RequireCleanState) {
    Assert-Administrator
    foreach ($program in @('bcdedit.exe', 'pnputil.exe', 'sc.exe')) {
        if (-not (Get-Command $program -ErrorAction SilentlyContinue)) {
            throw "required Windows command is unavailable: $program"
        }
    }
    foreach ($command in @('Get-Service', 'Start-Service', 'Stop-Service')) {
        if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
            throw "required SCM PowerShell command is unavailable: $command"
        }
    }
    Assert-TestSigning
    if ($RequireCleanState) {
        Assert-CleanDriverState
    }
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

function Assert-Bundle([string]$BundlePath) {
    $resolvedBundle = (Resolve-Path -LiteralPath $BundlePath).Path
    $verifiedParent = (Resolve-Path -LiteralPath (Join-Path $RepositoryRoot 'target\verified-production')).Path
    if ((Split-Path -Parent $resolvedBundle) -ne $verifiedParent) {
        throw 'bundle is outside target\verified-production'
    }
    $manifestPath = Join-Path $resolvedBundle 'manifest-v1.txt'
    $manifest = Read-KeyValueFile $manifestPath
    if ($manifest.manifest_version -ne '1') {
        throw 'unsupported production bundle manifest version'
    }
    if ((Split-Path -Leaf $resolvedBundle) -ne $manifest.artifact_id) {
        throw 'bundle directory identity differs from its manifest'
    }
    $artifactPaths = [ordered]@{
        ir = 'ext4win.ll'
        map = 'ext4win.map'
        sys = 'ext4win.sys'
        cat = 'ext4win.cat'
        inf = 'ext4win.inf'
    }
    foreach ($artifact in $artifactPaths.Keys) {
        $pathKey = "artifact.$artifact.path"
        $hashKey = "artifact.$artifact.sha256"
        if ([string]$manifest[$pathKey] -cne $artifactPaths[$artifact]) {
            throw "bundle artifact path is not canonical: $artifact"
        }
        $artifactPath = Join-Path $resolvedBundle $artifactPaths[$artifact]
        $actualHash = Get-Sha256FileHash $artifactPath
        if ($actualHash -ne [string]$manifest[$hashKey]) {
            throw "bundle artifact hash mismatch: $artifact"
        }
    }
    return [ordered]@{
        path = $resolvedBundle
        artifact_id = [string]$manifest.artifact_id
        sys_hash = [string]$manifest['artifact.sys.sha256']
        sys_path = (Join-Path $resolvedBundle 'ext4win.sys')
        inf_path = (Join-Path $resolvedBundle 'ext4win.inf')
    }
}

function Get-BundleSignerThumbprint($BundleIdentity) {
    $signature = Get-AuthenticodeSignature -LiteralPath $BundleIdentity.sys_path
    if (-not $signature.SignerCertificate -or -not $signature.SignerCertificate.Thumbprint) {
        throw 'verified production SYS has no Authenticode signer certificate identity'
    }
    return [string]$signature.SignerCertificate.Thumbprint
}

function Assert-BundleInstallationTrust($BundleIdentity) {
    $signature = Get-AuthenticodeSignature -LiteralPath $BundleIdentity.sys_path
    if (-not $signature.SignerCertificate -or -not $signature.SignerCertificate.Thumbprint) {
        throw 'verified production SYS has no Authenticode signer certificate identity'
    }
    $thumbprint = [string]$signature.SignerCertificate.Thumbprint
    foreach ($store in @('Root', 'TrustedPublisher')) {
        $certificatePath = "Cert:\LocalMachine\$store\$thumbprint"
        if (-not (Test-Path -LiteralPath $certificatePath)) {
            throw "production signer $thumbprint is absent from LocalMachine\$store"
        }
    }
    if ([string]$signature.Status -ne 'Valid') {
        throw "verified production SYS Authenticode status is $($signature.Status) after trust validation"
    }
    return $thumbprint
}

function Set-StateValue([string]$Name, [string]$Value) {
    if ($Name.Contains('=') -or $Name.Contains("`n") -or $Value.Contains("`r") -or $Value.Contains("`n")) {
        throw 'session manifest keys and values must be single-line records'
    }
    $script:State[$Name] = $Value
}

function Write-Phase([string]$Phase) {
    $sequence = 0
    if ($script:State.Contains('phase_sequence')) {
        $sequence = [int]$script:State.phase_sequence + 1
    }
    Set-StateValue 'phase_sequence' ([string]$sequence)
    Set-StateValue 'phase' $Phase
    $finalPath = Join-Path $script:SessionDirectory ('session-v1-{0:D4}.manifest' -f $sequence)
    $pendingPath = "$finalPath-$([Guid]::NewGuid().ToString('N')).pending"
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
    [IO.File]::Move($pendingPath, $finalPath)
}

function Load-Session([string]$RequestedSessionId) {
    Assert-SessionId $RequestedSessionId
    $parent = (Resolve-Path -LiteralPath $sessionParent).Path
    $candidate = Join-Path $parent $RequestedSessionId
    $resolved = (Resolve-Path -LiteralPath $candidate).Path
    if ((Split-Path -Parent $resolved) -ne $parent -or (Split-Path -Leaf $resolved) -cne $RequestedSessionId) {
        throw 'session path escaped the driver-load session root'
    }
    $latest = Get-ChildItem -LiteralPath $resolved -Filter 'session-v1-*.manifest' -File | Sort-Object Name | Select-Object -Last 1
    if (-not $latest) {
        throw 'driver-load session has no durable manifest'
    }
    $script:SessionDirectory = $resolved
    $script:State = Read-KeyValueFile $latest.FullName
    if ($script:State.manifest_version -ne '1' -or $script:State.session_id -cne $RequestedSessionId) {
        throw 'driver-load session manifest identity mismatch'
    }
    if ($script:State.service_name -cne $serviceName) {
        throw 'driver-load session service identity mismatch'
    }
    $bundleIdentity = Assert-Bundle $script:State.bundle_path
    if ($bundleIdentity.path -ne $script:State.bundle_path -or
        $bundleIdentity.artifact_id -cne $script:State.artifact_id -or
        $bundleIdentity.sys_hash -ne $script:State.sys_hash) {
        throw 'driver-load session artifact identity no longer matches the verified bundle'
    }
    $signerThumbprint = Get-BundleSignerThumbprint $bundleIdentity
    if ($signerThumbprint -ne $script:State.signer_thumbprint) {
        throw 'driver-load session signer identity no longer matches the verified bundle'
    }
    $script:SessionEstablished = $true
    return $bundleIdentity
}

function Assert-PackageShape($Package) {
    $driverFiles = @($Package.Files.File | Where-Object { [string]$_.Name -ieq 'ext4win.sys' })
    if ($driverFiles.Count -ne 1) {
        throw 'structured DriverStore inventory did not identify exactly one ext4win.sys in the selected package'
    }
}

function Export-And-VerifyPackage($Package, [string]$ExpectedHash) {
    Assert-PackageShape $Package
    $exportPath = Join-Path $script:SessionDirectory ("driverstore-export-{0}" -f [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $exportPath | Out-Null
    Invoke-Checked 'pnputil.exe' @('/export-driver', [string]$Package.DriverName, $exportPath) 'DriverStore package export' | Out-Null
    $drivers = @(Get-ChildItem -LiteralPath $exportPath -Filter 'ext4win.sys' -File -Recurse)
    if ($drivers.Count -ne 1) {
        throw 'exported DriverStore package did not contain exactly one ext4win.sys'
    }
    $actualHash = Get-Sha256FileHash $drivers[0].FullName
    if ($actualHash -ne $ExpectedHash) {
        throw 'exported DriverStore SYS hash differs from the verified production bundle'
    }
    Write-Host "exported DriverStore SYS SHA-256: $actualHash"
    return $drivers[0].FullName
}

function Resolve-ServiceImagePath([string]$ImagePath) {
    $expanded = [Environment]::ExpandEnvironmentVariables($ImagePath.Trim())
    $systemRootPrefix = '\SystemRoot\'
    $objectManagerPrefix = '\??\'
    if ($expanded.StartsWith($systemRootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        $expanded = Join-Path $env:SystemRoot $expanded.Substring($systemRootPrefix.Length)
    }
    elseif ($expanded.StartsWith($objectManagerPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        $expanded = $expanded.Substring($objectManagerPrefix.Length)
    }
    if (-not [IO.Path]::IsPathRooted($expanded)) {
        throw 'ext4win service ImagePath is not an absolute or SystemRoot-relative path'
    }
    return [IO.Path]::GetFullPath($expanded)
}

function Assert-ServiceConfiguration([string]$ExpectedHash, [bool]$RequireImageFile) {
    if (-not (Test-Path -LiteralPath $serviceRegistryPath)) {
        throw 'ext4win service registry entry is absent'
    }
    $configuration = Get-ItemProperty -LiteralPath $serviceRegistryPath
    if ([uint32]$configuration.Type -ne 2) {
        throw "ext4win service Type is $($configuration.Type), expected filesystem driver Type=2"
    }
    if ([uint32]$configuration.Start -ne 3) {
        throw "ext4win service Start is $($configuration.Start), expected demand start Start=3"
    }
    $rawImagePath = [string]$configuration.ImagePath
    $resolvedImagePath = Resolve-ServiceImagePath $rawImagePath
    $driverStoreRoot = (Resolve-Path -LiteralPath (Join-Path $env:SystemRoot 'System32\DriverStore\FileRepository')).Path.TrimEnd('\') + '\'
    $packageDirectoryName = Split-Path -Leaf (Split-Path -Parent $resolvedImagePath)
    if (-not $resolvedImagePath.StartsWith($driverStoreRoot, [StringComparison]::OrdinalIgnoreCase) -or
        (Split-Path -Leaf $resolvedImagePath) -ine 'ext4win.sys' -or
        $packageDirectoryName -inotmatch '^ext4win\.inf_') {
        throw 'ext4win service ImagePath does not select ext4win.sys below DriverStore\FileRepository'
    }
    if ($script:State.Contains('service_image_path') -and $script:State.service_image_path -ne $resolvedImagePath) {
        throw 'ext4win service ImagePath differs from the durable session identity'
    }
    if ($script:State.Contains('service_image_path_raw') -and $script:State.service_image_path_raw -cne $rawImagePath) {
        throw 'ext4win service raw ImagePath differs from the durable session identity'
    }
    if (Test-Path -LiteralPath $resolvedImagePath) {
        $imageHash = Get-Sha256FileHash $resolvedImagePath
        if ($imageHash -ne $ExpectedHash) {
            throw 'service DriverStore ImagePath SYS hash differs from the verified production bundle'
        }
        Write-Host "service ImagePath SYS SHA-256: $imageHash"
    }
    elseif ($RequireImageFile) {
        throw 'service DriverStore ImagePath SYS is absent'
    }
    Set-StateValue 'service_image_path' $resolvedImagePath
    Set-StateValue 'service_image_path_raw' $rawImagePath
    Write-Host 'service registry: Type=2 Start=3'
    Write-Host "service ImagePath: $resolvedImagePath"
}

function Get-InstalledSessionPackage([bool]$AllowRecovery) {
    $inventoryPath = Join-Path $script:SessionDirectory ("inventory-{0}.xml" -f [Guid]::NewGuid().ToString('N'))
    $packages = @(Get-Ext4WinPackages $inventoryPath)
    if ($packages.Count -gt 1) {
        throw 'more than one ext4win DriverStore package exists; session identity is ambiguous'
    }
    if ($packages.Count -eq 0) {
        return $null
    }
    $package = $packages[0]
    if ($script:State.Contains('oem_inf') -and $script:State.oem_inf) {
        if ([string]$package.DriverName -cne $script:State.oem_inf) {
            throw 'the remaining ext4win package does not match the durable OEM INF identity'
        }
    }
    elseif ($AllowRecovery) {
        Export-And-VerifyPackage $package $script:State.sys_hash | Out-Null
        Set-StateValue 'oem_inf' ([string]$package.DriverName)
        Write-Phase 'PackageIdentityRecovered'
    }
    else {
        throw 'installed ext4win package lacks a durable OEM INF identity'
    }
    Assert-PackageShape $package
    return $package
}

function Assert-InstalledDriverIdentity {
    $package = Get-InstalledSessionPackage $false
    if (-not $package) {
        throw 'the session ext4win DriverStore package is absent'
    }
    $exportedSys = Export-And-VerifyPackage $package $script:State.sys_hash
    Set-StateValue 'exported_sys_path' $exportedSys
    Assert-ServiceConfiguration $script:State.sys_hash $true
    return $package
}

function Start-DriverLoadSession([string]$BundlePath, [string]$RequestedSessionId) {
    Assert-HostContract $true
    Assert-SessionId $RequestedSessionId
    $bundleIdentity = Assert-Bundle $BundlePath
    $signerThumbprint = Assert-BundleInstallationTrust $bundleIdentity
    Write-Output "certificate LocalMachine\Root thumbprint: $signerThumbprint"
    Write-Output "certificate LocalMachine\TrustedPublisher thumbprint: $signerThumbprint"
    New-Item -ItemType Directory -Path $sessionParent -Force | Out-Null
    $script:SessionDirectory = Join-Path $sessionParent $RequestedSessionId
    New-Item -ItemType Directory -Path $script:SessionDirectory | Out-Null
    Set-StateValue 'manifest_version' '1'
    Set-StateValue 'session_id' $RequestedSessionId
    Set-StateValue 'artifact_id' $bundleIdentity.artifact_id
    Set-StateValue 'bundle_path' $bundleIdentity.path
    Set-StateValue 'sys_hash' $bundleIdentity.sys_hash
    Set-StateValue 'signer_thumbprint' $signerThumbprint
    Set-StateValue 'service_name' $serviceName
    Set-StateValue 'service_started' 'false'
    Write-Phase 'SessionCreated'
    $script:SessionEstablished = $true

    Write-Phase 'PackageInstallRequested'
    Invoke-Checked 'pnputil.exe' @('/add-driver', $bundleIdentity.inf_path, '/install') 'ext4win package installation'
    $inventoryPath = Join-Path $script:SessionDirectory ("inventory-installed-{0}.xml" -f [Guid]::NewGuid().ToString('N'))
    $packages = @(Get-Ext4WinPackages $inventoryPath)
    if ($packages.Count -ne 1) {
        throw 'installation did not produce exactly one ext4win DriverStore package'
    }
    Set-StateValue 'oem_inf' ([string]$packages[0].DriverName)
    Assert-InstalledDriverIdentity | Out-Null
    Write-Phase 'PackageInstalled'

    Write-Phase 'ServiceStartRequested'
    Start-Service -Name $serviceName -ErrorAction Stop
    $service = Get-Service -Name $serviceName -ErrorAction Stop
    $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(15))
    if ($service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) {
        throw "ext4win service state is $($service.Status), expected Running"
    }
    Set-StateValue 'service_started' 'true'
    Assert-InstalledDriverIdentity | Out-Null
    Invoke-Checked 'sc.exe' @('query', $serviceName) 'ext4win running-state diagnostic query'
    Write-Output 'service state: Running'
    Write-Phase 'ServiceRunning'
}

function Cleanup-DriverLoadSession {
    if ($script:State.phase -eq 'Complete') {
        Write-Output 'driver-load session is already complete'
        return
    }

    $package = Get-InstalledSessionPackage $true
    $serviceExists = (Test-Path -LiteralPath $serviceRegistryPath) -or [bool](Get-Service -Name $serviceName -ErrorAction SilentlyContinue)
    if ($serviceExists) {
        Assert-ServiceConfiguration $script:State.sys_hash ([bool]$package)
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service -and $service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
            Write-Phase 'CleanupServiceStopRequested'
            Stop-Service -Name $serviceName -ErrorAction Stop
            $service = Get-Service -Name $serviceName -ErrorAction Stop
            $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(15))
            if ($service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
                throw "ext4win service state is $($service.Status), expected Stopped"
            }
            Set-StateValue 'service_started' 'false'
            Invoke-Checked 'sc.exe' @('query', $serviceName) 'ext4win stopped-state diagnostic query'
            Write-Phase 'CleanupServiceStopped'
        }
    }

    if ($package) {
        Export-And-VerifyPackage $package $script:State.sys_hash | Out-Null
        Write-Phase 'CleanupPackageRemovalRequested'
        Invoke-Checked 'pnputil.exe' @('/delete-driver', [string]$package.DriverName, '/uninstall', '/force') 'session DriverStore package removal'
        Write-Phase 'CleanupPackageRemoved'
    }

    if ((Test-Path -LiteralPath $serviceRegistryPath) -or (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) {
        Write-Phase 'CleanupServiceDeleteRequested'
        Invoke-Checked 'sc.exe' @('delete', $serviceName) 'session service deletion'
        for ($attempt = 0; $attempt -lt 20; $attempt++) {
            if (-not (Test-Path -LiteralPath $serviceRegistryPath) -and -not (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) {
                break
            }
            Start-Sleep -Milliseconds 250
        }
        Write-Phase 'CleanupServiceDeleted'
    }

    $finalInventory = Join-Path $script:SessionDirectory ("inventory-final-{0}.xml" -f [Guid]::NewGuid().ToString('N'))
    if (@(Get-Ext4WinPackages $finalInventory).Count -ne 0) {
        throw 'ext4win DriverStore package remains after cleanup'
    }
    if ((Test-Path -LiteralPath $serviceRegistryPath) -or (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) {
        throw 'ext4win service remains after cleanup'
    }
    Write-Output 'cleanup service/package absence: PASS'
    Write-Phase 'Complete'
}

function Run-HostedDriverLoad([string]$BundlePath, [string]$RequestedSessionId) {
    $operationError = $null
    try {
        Start-DriverLoadSession $BundlePath $RequestedSessionId
    }
    catch {
        $operationError = $_
    }

    $cleanupError = $null
    if ($script:SessionEstablished) {
        try {
            Cleanup-DriverLoadSession
        }
        catch {
            $cleanupError = $_
        }
    }
    if ($operationError -and $cleanupError) {
        throw "driver-load operation failed ($operationError); mandatory cleanup also failed ($cleanupError)"
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
        Assert-HostContract $true
        Write-Output 'hosted driver-load host contract: PASS'
    }
    'Start' {
        if (-not $Bundle -or -not $SessionId) {
            throw 'Start requires generated Bundle and SessionId arguments'
        }
        Start-DriverLoadSession $Bundle $SessionId
    }
    'Run' {
        if (-not $Bundle -or -not $SessionId) {
            throw 'Run requires generated Bundle and SessionId arguments'
        }
        Run-HostedDriverLoad $Bundle $SessionId
    }
    'Cleanup' {
        Assert-Administrator
        if (-not $SessionId) {
            throw 'Cleanup requires a generated SessionId argument'
        }
        Load-Session $SessionId | Out-Null
        Cleanup-DriverLoadSession
    }
}
