# Local dead-man switch for the NetRiser block simulation (nr-sim-block).
#
# Arms a scheduled task that runs as SYSTEM on this computer, so it works even
# when every remote connection is lost. When it fires (after -Minutes, or at
# the next Windows startup, whichever comes first) it undoes the simulation:
#   1. nr blockers restore <service>  (removes NetRiser's record, if any)
#   2. ends the blocker process (its WFP filter disappears with it)
#   3. deletes the blocker service, its files and the task itself
# Everything is logged to C:\ProgramData\nr-sim\restore.log.
#
#   sim-timer.ps1 -Minutes 20     arm (or re-arm)
#   sim-timer.ps1 -Now            undo the simulation now
#   sim-timer.ps1 -Cancel         disarm, leave the simulation as it is
#
# Run as Administrator. ASCII only, so any PowerShell reads it correctly.

param(
    [int]$Minutes = 20,
    [switch]$Now,
    [switch]$Cancel,
    [string]$ServiceName = 'NrSimBlock',
    [string]$ProcessName = 'nr-sim-block'
)
$ErrorActionPreference = 'Stop'
$TaskName = 'NrSimRestore'
$Dir = Join-Path $env:ProgramData 'nr-sim'
$Restore = Join-Path $Dir 'restore.ps1'
New-Item -ItemType Directory -Force -Path $Dir | Out-Null

$body = @"
`$log = '$Dir\restore.log'
function L([string]`$m) { Add-Content -LiteralPath `$log -Value ((Get-Date -Format 'yyyy-MM-dd HH:mm:ss ') + `$m) }
L 'restore: started'
`$nr = 'C:\Program Files\NetRiser\nr.cmd'
if (Test-Path -LiteralPath `$nr) { L ('nr blockers restore: ' + ((& `$nr blockers restore $ServiceName 2>&1) -join ' | ')) }
Get-Process -Name '$ProcessName' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
L ('process left: ' + [bool](Get-Process -Name '$ProcessName' -ErrorAction SilentlyContinue))
L ('sc delete: ' + ((& sc.exe delete $ServiceName 2>&1) -join ' '))
Unregister-ScheduledTask -TaskName '$TaskName' -Confirm:`$false -ErrorAction SilentlyContinue
L 'restore: done'
"@
Set-Content -LiteralPath $Restore -Value $body -Encoding ASCII

if ($Cancel) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "Timer $TaskName disarmed."
    return
}
if ($Now) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Restore
    Get-Content -LiteralPath (Join-Path $Dir 'restore.log') -Tail 6
    return
}

$at = (Get-Date).AddMinutes($Minutes)
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$Restore`""
$triggers = @((New-ScheduledTaskTrigger -Once -At $at), (New-ScheduledTaskTrigger -AtStartup))
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $triggers -Principal $principal -Settings $settings -Force | Out-Null
$task = Get-ScheduledTask -TaskName $TaskName
Write-Host ("Timer {0} armed: undoes the simulation at {1:HH:mm:ss} or at the next Windows startup ({2})." -f $TaskName, $at, $task.State)
