<#
.SYNOPSIS
Registers, exports, observes or removes a UUID-scoped Windows TRIM task.
.DESCRIPTION
Windows owns the weekly local-time trigger and execution history. Registration creates
one task without replacing an existing definition or starting it. Edit its cadence in
Task Scheduler. Remove prevents future starts without stopping a running scan.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Register', 'Export', 'Show', 'Remove')]
    [string]$Action,

    [Parameter(Mandatory)]
    [guid]$FilesystemUuid,

    [string]$Executable,
    [System.DayOfWeek]$Day = [System.DayOfWeek]::Sunday,

    [ValidatePattern('^(?:[01][0-9]|2[0-3]):[0-5][0-9]$')]
    [string]$At = '03:00'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$uuid = $FilesystemUuid.ToString('D')
$taskName = "ext4win-TRIM-$uuid"
$source = 'ext4win free-space TRIM'

if ($Action -in @('Register', 'Export')) {
    if ([string]::IsNullOrWhiteSpace($Executable)) {
        throw 'Register and Export require -Executable with the installed ext4ctl.exe path.'
    }
    $program = Get-Item -LiteralPath $Executable
    if ($program.PSIsContainer -or $program.Extension -ine '.exe') {
        throw 'The task executable must be an existing Windows executable file.'
    }
}

$service = New-Object -ComObject 'Schedule.Service'
$service.Connect()
$folder = $service.GetFolder('\')

if ($Action -in @('Show', 'Remove')) {
    $registered = $folder.GetTask($taskName)
    if (([xml]$registered.Xml).Task.RegistrationInfo.Source -ne $source) {
        throw "The task named $taskName is not an ext4win TRIM registration."
    }
    if ($Action -eq 'Show') {
        [pscustomobject]@{
            TaskName = $registered.Name
            State = $registered.State
            LastRunTime = $registered.LastRunTime
            LastTaskResult = $registered.LastTaskResult
            NextRunTime = $registered.NextRunTime
            Definition = $registered.Xml
        }
    } elseif ($PSCmdlet.ShouldProcess($taskName, 'Remove future TRIM starts')) {
        try {
            $folder.DeleteTask($taskName, 0)
        } catch {
            $record = [System.Management.Automation.ErrorRecord]::new(
                $_.Exception, 'TrimTaskRemovalUnacknowledged',
                [System.Management.Automation.ErrorCategory]::InvalidResult, $taskName)
            $record.ErrorDetails = [System.Management.Automation.ErrorDetails]::new(
                "Removal was not acknowledged. Query Task Scheduler before repeating removal. $($_.Exception.Message)")
            $PSCmdlet.ThrowTerminatingError($record)
        }
    }
    return
}

$definition = $service.NewTask(0)
$definition.RegistrationInfo.Source = $source
$definition.RegistrationInfo.Description = "Discard checkpointed ext4 free space for UUID $uuid."
$definition.Principal.UserId = 'S-1-5-18' # LocalSystem, independent of account-name localization.
$definition.Principal.LogonType = 5 # TASK_LOGON_SERVICE_ACCOUNT; no saved password.
$definition.Principal.RunLevel = 1 # TASK_RUNLEVEL_HIGHEST.
$definition.Settings.MultipleInstances = 2 # TASK_INSTANCES_IGNORE_NEW.
$definition.Settings.StartWhenAvailable = $true
$definition.Settings.DisallowStartIfOnBatteries = $true
$definition.Settings.StopIfGoingOnBatteries = $false
$definition.Settings.AllowHardTerminate = $false
$definition.Settings.ExecutionTimeLimit = 'PT0S'
$definition.Settings.RestartCount = 0
$definition.Settings.Enabled = $true

$trigger = $definition.Triggers.Create(3) # TASK_TRIGGER_WEEKLY.
$clock = [timespan]::ParseExact($At, 'hh\:mm', [cultureinfo]::InvariantCulture)
$start = [datetime]::Today.AddDays(([int]$Day - [int][datetime]::Today.DayOfWeek + 7) % 7).Add($clock)
if ($start -le [datetime]::Now) { $start = $start.AddDays(7) }
$trigger.StartBoundary = $start.ToString('yyyy-MM-ddTHH:mm:ss', [cultureinfo]::InvariantCulture)
$trigger.DaysOfWeek = 1 -shl [int]$Day
$trigger.WeeksInterval = 1
$trigger.Enabled = $true

$command = $definition.Actions.Create(0) # TASK_ACTION_EXEC; no intervening shell.
$command.Path = $program.FullName
$command.Arguments = "trim $uuid"
$command.WorkingDirectory = $program.DirectoryName

if ($Action -eq 'Export') {
    $definition.XmlText
} elseif ($PSCmdlet.ShouldProcess($taskName, 'Register weekly TRIM task')) {
    try {
        # TASK_CREATE refuses to replace an existing task. Future changes belong to Windows.
        $registered = $folder.RegisterTaskDefinition($taskName, $definition, 2, 'S-1-5-18', $null, 5)
        [pscustomobject]@{ TaskName = $registered.Name; NextRunTime = $registered.NextRunTime }
    } catch {
        $record = [System.Management.Automation.ErrorRecord]::new(
            $_.Exception, 'TrimTaskRegistrationUnacknowledged',
            [System.Management.Automation.ErrorCategory]::InvalidResult, $taskName)
        $record.ErrorDetails = [System.Management.Automation.ErrorDetails]::new(
            "Registration was not acknowledged. Query Task Scheduler before repeating registration. $($_.Exception.Message)")
        $PSCmdlet.ThrowTerminatingError($record)
    }
}
