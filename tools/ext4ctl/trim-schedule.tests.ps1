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

function Assert-TaskContract(
    [xml]$Document,
    [System.DayOfWeek]$ExpectedDay = $arguments.Day,
    [string]$ExpectedTime = $arguments.At
) {
    $namespace = [System.Xml.XmlNamespaceManager]::new($Document.NameTable)
    $namespace.AddNamespace('t', 'http://schemas.microsoft.com/windows/2004/02/mit/task')
    $expected = @{
        '/t:Task/t:Principals/t:Principal/t:UserId' = 'S-1-5-18'
        '/t:Task/t:Principals/t:Principal/t:RunLevel' = 'HighestAvailable'
        '/t:Task/t:Settings/t:MultipleInstancesPolicy' = 'IgnoreNew'
        '/t:Task/t:Settings/t:StartWhenAvailable' = 'true'
        '/t:Task/t:Settings/t:DisallowStartIfOnBatteries' = 'true'
        '/t:Task/t:Settings/t:StopIfGoingOnBatteries' = 'false'
        '/t:Task/t:Settings/t:AllowHardTerminate' = 'false'
        '/t:Task/t:Settings/t:ExecutionTimeLimit' = 'PT0S'
        '/t:Task/t:Settings/t:Enabled' = 'true'
        '/t:Task/t:Actions/t:Exec/t:Command' = $executable
        '/t:Task/t:Actions/t:Exec/t:Arguments' = "trim $($uuid.ToString('D'))"
        '/t:Task/t:Triggers/t:CalendarTrigger/t:ScheduleByWeek/t:WeeksInterval' = '1'
        '/t:Task/t:Triggers/t:CalendarTrigger/t:Enabled' = 'true'
    }
    foreach ($path in $expected.Keys) {
        $node = $Document.SelectSingleNode($path, $namespace)
        if ($null -eq $node -or $node.InnerText -cne $expected[$path]) {
            throw "Native task contract failed at $path"
        }
    }
    $start = $Document.SelectSingleNode('/t:Task/t:Triggers/t:CalendarTrigger/t:StartBoundary', $namespace)
    if ([datetime]::Parse($start.InnerText) -le [datetime]::Now) {
        throw 'Task registration can start before the explicitly selected future trigger.'
    }
    if ([datetime]::Parse($start.InnerText).ToString('HH:mm') -ne $ExpectedTime) {
        throw 'The native trigger does not match the selected local clock time.'
    }
    $days = $Document.SelectSingleNode('/t:Task/t:Triggers/t:CalendarTrigger/t:ScheduleByWeek/t:DaysOfWeek', $namespace)
    if ($days.ChildNodes.Count -ne 1 -or $days.FirstChild.LocalName -ne $ExpectedDay.ToString()) {
        throw 'The native weekly trigger does not match the selected local day.'
    }
    if ($null -ne $Document.SelectSingleNode('/t:Task/t:Settings/t:RestartOnFailure', $namespace)) {
        throw 'An uncertain TRIM result must not cause automatic failure retries.'
    }
}

Assert-TaskContract ([xml](& $scriptPath -Action Export @arguments))
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
    $service = New-Object -ComObject 'Schedule.Service'
    $service.Connect()
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
