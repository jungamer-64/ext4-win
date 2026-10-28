# Native Task Scheduler definitions are constructed from the current production script.
# Registration validation owns one temporary task with an inert action and a future trigger.
[CmdletBinding()]
param([switch]$Registration)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path $PSScriptRoot 'trim-schedule.ps1'
$uuid = [guid]::NewGuid()
$executable = Join-Path $env:SystemRoot 'System32\whoami.exe'
$arguments = @{
    FilesystemUuid = $uuid
    Executable = $executable
    Day = [datetime]::Today.AddDays(1).DayOfWeek
    At = '12:34'
}
$service = New-Object -ComObject 'Schedule.Service'
$service.Connect()

function Assert-TaskContract(
    [xml]$Document,
    [System.DayOfWeek]$ExpectedDay = $arguments.Day,
    [string]$ExpectedTime = $arguments.At
) {
    # Task Scheduler owns XML defaults and account-name normalization.
    $definition = $service.NewTask(0)
    $definition.XmlText = $Document.OuterXml
    $identity = $definition.Principal.UserId
    if ($identity -notmatch '^S-1-') {
        $identity = [System.Security.Principal.NTAccount]::new($identity).
            Translate([System.Security.Principal.SecurityIdentifier]).Value
    }
    if ($definition.Triggers.Count -ne 1 -or $definition.Actions.Count -ne 1) {
        throw 'The task must contain exactly one weekly trigger and one executable action.'
    }
    $trigger = $definition.Triggers.Item(1)
    $command = $definition.Actions.Item(1)
    $checks = @{
        'Principal.UserId' = @($identity, 'S-1-5-18')
        'Principal.LogonType' = @($definition.Principal.LogonType, 5)
        'Principal.RunLevel' = @($definition.Principal.RunLevel, 1)
        'Settings.MultipleInstances' = @($definition.Settings.MultipleInstances, 2)
        'Settings.StartWhenAvailable' = @($definition.Settings.StartWhenAvailable, $true)
        'Settings.DisallowStartIfOnBatteries' = @($definition.Settings.DisallowStartIfOnBatteries, $true)
        'Settings.StopIfGoingOnBatteries' = @($definition.Settings.StopIfGoingOnBatteries, $false)
        'Settings.AllowHardTerminate' = @($definition.Settings.AllowHardTerminate, $false)
        'Settings.ExecutionTimeLimit' = @($definition.Settings.ExecutionTimeLimit, 'PT0S')
        'Settings.Enabled' = @($definition.Settings.Enabled, $true)
        'Settings.RestartCount' = @($definition.Settings.RestartCount, 0)
        'Action.Type' = @($command.Type, 0)
        'Action.Path' = @($command.Path, $executable)
        'Action.Arguments' = @($command.Arguments, "trim $($uuid.ToString('D'))")
        'Trigger.Type' = @($trigger.Type, 3)
        'Trigger.WeeksInterval' = @($trigger.WeeksInterval, 1)
        'Trigger.Enabled' = @($trigger.Enabled, $true)
        'Trigger.DaysOfWeek' = @($trigger.DaysOfWeek, (1 -shl [int]$ExpectedDay))
    }
    foreach ($field in $checks.Keys) {
        $actual, $expected = $checks[$field]
        if ($actual -cne $expected) {
            throw "Native task contract failed at $field"
        }
    }
    $start = [datetime]::Parse($trigger.StartBoundary)
    if ($start -le [datetime]::Now) {
        throw 'Task registration can start before the explicitly selected future trigger.'
    }
    if ($start.ToString('HH:mm') -ne $ExpectedTime) {
        throw 'The native trigger does not match the selected local clock time.'
    }
}

$document = [xml](& $scriptPath -Action Export @arguments)
Assert-TaskContract $document
# Omitted defaults and explicitly disabled values must retain their native meaning.
$namespace = [System.Xml.XmlNamespaceManager]::new($document.NameTable)
$namespace.AddNamespace('t', 'http://schemas.microsoft.com/windows/2004/02/mit/task')
foreach ($node in @($document.SelectNodes('//t:Enabled', $namespace))) {
    $null = $node.ParentNode.RemoveChild($node)
}
Assert-TaskContract $document
foreach ($field in @('Settings.Enabled', 'Trigger.Enabled')) {
    $disabled = $service.NewTask(0)
    $disabled.XmlText = $document.OuterXml
    if ($field -eq 'Settings.Enabled') { $disabled.Settings.Enabled = $false }
    else { $disabled.Triggers.Item(1).Enabled = $false }
    $rejected = $false
    try { Assert-TaskContract ([xml]$disabled.XmlText) }
    catch { $rejected = $_.Exception.Message -ceq "Native task contract failed at $field" }
    if (-not $rejected) { throw "A disabled native task field was admitted: $field" }
}
Assert-TaskContract ([xml](& $scriptPath -Action Export -FilesystemUuid $uuid -Executable $executable)) `
    -ExpectedDay Sunday -ExpectedTime '03:00'
foreach ($invalid in @('24:00', '12:60', '3:00', '12:34 extra')) {
    $rejected = $false
    try { & $scriptPath -Action Export -FilesystemUuid $uuid -Executable $executable -At $invalid }
    catch { $rejected = $_.FullyQualifiedErrorId -like '*ParameterArgumentValidationError*' }
    if (-not $rejected) { throw "Invalid local clock time was admitted: $invalid" }
}

if ($Registration) {
    $taskName = "ext4win-TRIM-$($uuid.ToString('D'))"
    $folder = $service.GetFolder('\')
    try {
        $registered = & $scriptPath -Action Register @arguments -Confirm:$false
        if ($registered.TaskName -ne $taskName) { throw 'Unexpected task registration identity.' }
        $observed = & $scriptPath -Action Show -FilesystemUuid $uuid
        Assert-TaskContract ([xml]$observed.Definition)
        $refused = $false
        try { & $scriptPath -Action Register @arguments -Confirm:$false }
        catch {
            $cause = $_.Exception
            while ($null -ne $cause.InnerException) { $cause = $cause.InnerException }
            $refused = $cause.HResult -eq -2147024713 # ERROR_ALREADY_EXISTS.
        }
        if (-not $refused) { throw 'Task registration replaced an existing Windows definition.' }
    } finally {
        $retained = @($folder.GetTasks(1) | Where-Object { $_.Name -eq $taskName })
        if ($retained.Count -gt 0) {
            & $scriptPath -Action Remove -FilesystemUuid $uuid -Confirm:$false
        }
    }
    if (@($folder.GetTasks(1) | Where-Object { $_.Name -eq $taskName }).Count -ne 0) {
        throw 'Temporary Task Scheduler registration was not removed.'
    }
}
Write-Output 'Windows TRIM task contracts: PASS'
