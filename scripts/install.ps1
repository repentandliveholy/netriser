# NetRiser installer for Windows PowerShell. Run from an elevated shell.
$ErrorActionPreference = 'Stop'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Administrator privileges are required. Reopen PowerShell as Administrator.'
}

$DistUrl = if ($env:NETRISER_URL) { $env:NETRISER_URL } elseif ($env:WATCHDOG_URL) { $env:WATCHDOG_URL } else { 'https://netriser.repentandliveholy.org' }
$BinDir = Join-Path $env:ProgramFiles 'NetRiser'
$BinPath = Join-Path $BinDir 'netriser.exe'
$StagePath = Join-Path $BinDir ".netriser-$([guid]::NewGuid().ToString('N')).new"
$LegacyDir = Join-Path $env:ProgramFiles 'mesh-watchdog'
$LegacyPath = Join-Path $LegacyDir 'mesh-watchdog.exe'
$ProgramData = $env:ProgramData
$NewData = Join-Path $ProgramData 'netriser'
$LegacyData = Join-Path $ProgramData 'mesh-watchdog'
$TempDir = Join-Path $env:TEMP "netriser-$([guid]::NewGuid().ToString('N'))"
$TempPath = Join-Path $TempDir 'netriser-windows-amd64.exe'
$LegacyService = Get-CimInstance Win32_Service -Filter "Name='mesh-watchdog'" -ErrorAction SilentlyContinue
$NewService = Get-CimInstance Win32_Service -Filter "Name='netriser'" -ErrorAction SilentlyContinue
$LegacyWasRunning = $LegacyService -and $LegacyService.State -eq 'Running'
$NewWasRunning = $NewService -and $NewService.State -eq 'Running'
$LegacyConfig = $null
$Backup = $null
$Mutating = $false
$MachinePathBefore = $null
$ProcessPathBefore = $env:Path
$MachinePathChanged = $false
$ProcessPathChanged = $false

if ($LegacyService -and $LegacyService.PathName -match '--config(?:=|\s+)(?:"([^"]+)"|(\S+))') {
    $LegacyConfig = if ($Matches[1]) { $Matches[1] } else { $Matches[2] }
}
if (-not $LegacyConfig -and $NewService -and $NewService.PathName -match '--config(?:=|\s+)(?:"([^"]+)"|(\S+))') {
    $LegacyConfig = if ($Matches[1]) { $Matches[1] } else { $Matches[2] }
}

function Copy-BackupPath([string]$Path) {
    if ($Path -and (Test-Path -LiteralPath $Path)) {
        $relative = $Path -replace '^[A-Za-z]:\\', ''
        $destination = Join-Path $Backup (Join-Path 'files' $relative)
        $parent = Split-Path -Parent $destination
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
        Copy-Item -LiteralPath $Path -Destination $destination -Recurse -Force
    }
}
function Restore-BackupPath([string]$Path) {
    if (-not $Path) { return }
    $relative = $Path -replace '^[A-Za-z]:\\', ''
    $saved = Join-Path $Backup (Join-Path 'files' $relative)
    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Recurse -Force }
    if (Test-Path -LiteralPath $saved) {
        New-Item -ItemType Directory -Path (Split-Path -Parent $Path) -Force | Out-Null
        Copy-Item -LiteralPath $saved -Destination $Path -Recurse -Force
    }
}
function Restore-LegacyService {
    if (-not $LegacyService) { return }
    if ($LegacyService.StartMode -eq 'Auto') { Set-Service mesh-watchdog -StartupType Automatic -ErrorAction SilentlyContinue }
    elseif ($LegacyService.StartMode -eq 'Disabled') { Set-Service mesh-watchdog -StartupType Disabled -ErrorAction SilentlyContinue }
    else { Set-Service mesh-watchdog -StartupType Manual -ErrorAction SilentlyContinue }
    if ($LegacyWasRunning) { Start-Service mesh-watchdog -ErrorAction SilentlyContinue }
}
function Rollback-Install {
    if (-not $Backup -or -not $Mutating) { return }
    Write-Warning "Installation failed; restoring previous files and service state from $Backup"
    Stop-Service netriser -Force -ErrorAction SilentlyContinue
    if (-not $NewService) { & sc.exe delete netriser | Out-Null }
    foreach ($path in @($BinPath, (Join-Path $BinDir 'nr.cmd'), (Join-Path $BinDir 'mesh-watchdog.cmd'), $NewData, $LegacyData, $LegacyPath, $LegacyConfig)) {
        Restore-BackupPath $path
    }
    if ($NewWasRunning) { Start-Service netriser -ErrorAction SilentlyContinue }
    Restore-LegacyService
    if ($MachinePathChanged) { [Environment]::SetEnvironmentVariable('Path', $MachinePathBefore, 'Machine') }
    if ($ProcessPathChanged) { $env:Path = $ProcessPathBefore }
}

try {
    New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
    $asset = 'netriser-windows-amd64.exe'
    $base = $DistUrl.TrimEnd('/')
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri "$base/bin/$asset" -OutFile $TempPath
    $sumsPath = Join-Path $TempDir 'sha256sums.txt'
    Invoke-WebRequest -Uri "$base/sha256sums.txt" -OutFile $sumsPath
    $sumLine = Get-Content $sumsPath | Where-Object { $_ -match "\s+$([regex]::Escape($asset))$" } | Select-Object -First 1
    if (-not $sumLine -or $sumLine -notmatch '^([0-9a-fA-F]{64})\s+') { throw "No valid SHA-256 entry for $asset in sha256sums.txt." }
    $expectedHash = $Matches[1].ToLowerInvariant()
    $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $TempPath).Hash.ToLowerInvariant()
    if ($actualHash -ne $expectedHash) { throw 'Downloaded binary SHA-256 does not match the release checksum.' }
    $ProgressPreference = 'Continue'

    $Backup = Join-Path $ProgramData "NetRiser-Backups\migration-$([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'))-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $Backup -Force | Out-Null
    foreach ($path in @($BinPath, (Join-Path $BinDir 'nr.cmd'), (Join-Path $BinDir 'mesh-watchdog.cmd'), $LegacyPath, $NewData, $LegacyData, $LegacyConfig)) { Copy-BackupPath $path }
    if ($LegacyService) { & reg.exe export 'HKLM\SYSTEM\CurrentControlSet\Services\mesh-watchdog' (Join-Path $Backup 'legacy-service.reg') /y | Out-Null }
    if ($NewService) { & reg.exe export 'HKLM\SYSTEM\CurrentControlSet\Services\netriser' (Join-Path $Backup 'netriser-service.reg') /y | Out-Null }

    New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
    $Mutating = $true
    if ($NewWasRunning) { Stop-Service netriser -Force }
    if ($LegacyWasRunning) { Stop-Service mesh-watchdog -Force }
    if ($LegacyService) { Set-Service mesh-watchdog -StartupType Disabled }

    Copy-Item -LiteralPath $TempPath -Destination $StagePath
    if (Test-Path -LiteralPath $BinPath) {
        [System.IO.File]::Replace($StagePath, $BinPath, $null, $true)
    } else {
        Move-Item -LiteralPath $StagePath -Destination $BinPath
    }

    if ($LegacyConfig) {
        & $BinPath --config $LegacyConfig migrate
    } else {
        & $BinPath migrate
    }
    if ($LASTEXITCODE -ne 0) { throw "Configuration migration failed (exit $LASTEXITCODE)." }

    if ($NewService) {
        Restart-Service netriser -ErrorAction Stop
    } elseif ($LegacyConfig) {
        & $BinPath --config $LegacyConfig service install
    } else {
        & $BinPath service install
    }
    if ($LASTEXITCODE -ne 0) { throw "NetRiser service operation failed (exit $LASTEXITCODE)." }
    $serviceNow = Get-Service netriser -ErrorAction Stop
    if ($serviceNow.Status -ne 'Running') { throw 'NetRiser service did not remain running.' }

    # Command wrappers always execute the service binary, so self-update also
    # updates what the terminal command invokes.
    $wrapper = @('@echo off', '"%~dp0netriser.exe" %*', 'exit /b %ERRORLEVEL%') -join "`r`n"
    Set-Content -LiteralPath (Join-Path $BinDir 'nr.cmd') -Encoding ASCII -Value $wrapper
    Set-Content -LiteralPath (Join-Path $BinDir 'mesh-watchdog.cmd') -Encoding ASCII -Value $wrapper

    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $MachinePathBefore = $machinePath
    $pathParts = @($machinePath -split ';' | Where-Object { $_ })
    if (-not ($pathParts | Where-Object { $_.TrimEnd('\') -ieq $BinDir.TrimEnd('\') })) {
        $newPath = (@($pathParts) + @($BinDir)) -join ';'
        [Environment]::SetEnvironmentVariable('Path', $newPath, 'Machine')
        $MachinePathChanged = $true
    }
    if (-not (($env:Path -split ';') | Where-Object { $_.TrimEnd('\') -ieq $BinDir.TrimEnd('\') })) {
        $env:Path = "$BinDir;$env:Path"
        $ProcessPathChanged = $true
    }

    & $BinPath version
    if ($LegacyService) {
        & sc.exe delete mesh-watchdog | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Could not retire the stopped legacy service (exit $LASTEXITCODE)." }
    }
    Write-Host "NetRiser installed. Migration backup: $Backup" -ForegroundColor Green
} catch {
    Rollback-Install
    throw
} finally {
    Remove-Item -LiteralPath $StagePath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $TempDir -Recurse -Force -ErrorAction SilentlyContinue
}
