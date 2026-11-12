# NetRiser installer for Windows PowerShell. Run from an elevated shell.
$ErrorActionPreference = 'Stop'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Administrator privileges are required. Reopen PowerShell as Administrator.'
}

$DistUrl = if ($env:NETRISER_URL) { $env:NETRISER_URL } elseif ($env:WATCHDOG_URL) { $env:WATCHDOG_URL } else { 'https://netriser.repentandliveholy.org' }
$BinDir = Join-Path $env:ProgramFiles 'NetRiser'
$BinPath = Join-Path $BinDir 'netriser.exe'
$LicenseDir = Join-Path $BinDir 'licenses'
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
$LegacyConfig = $env:CONF_FILE
$Backup = $null
$Mutating = $false
$MachinePathBefore = $null
$ProcessPathBefore = $env:Path
$MachinePathChanged = $false
$ProcessPathChanged = $false

if (-not $LegacyConfig -and $LegacyService -and $LegacyService.PathName -match '--config(?:=|\s+)(?:"([^"]+)"|(\S+))') {
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
function Normalize-Choice([string]$Label, [string]$Supplied) {
    if (-not $Supplied) { return '' }
    switch ($Supplied.ToLowerInvariant()) {
        { $_ -in @('true', 'yes', 'y', '1', 'on') } { return 'true' }
        { $_ -in @('false', 'no', 'n', '0', 'off') } { return 'false' }
        default { throw "Invalid setting for ${Label}: use true or false." }
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
    if ($StagePath) { Remove-Item -LiteralPath $StagePath -Force -ErrorAction SilentlyContinue }
    foreach ($path in @($LicenseDir, $BinPath, (Join-Path $BinDir 'nr.cmd'), (Join-Path $BinDir 'mesh-watchdog.cmd'), $NewData, $LegacyData, $LegacyPath, $LegacyConfig)) {
        Restore-BackupPath $path
    }
    if ($NewWasRunning) { Start-Service netriser -ErrorAction SilentlyContinue }
    Restore-LegacyService
    if ($MachinePathChanged) { [Environment]::SetEnvironmentVariable('Path', $MachinePathBefore, 'Machine') }
    if ($ProcessPathChanged) { $env:Path = $ProcessPathBefore }
}

try {
    Write-Host '[1/8] NetRiser installation for windows/amd64; administrator access confirmed'
    New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
    $asset = 'netriser-windows-amd64.exe'
    $base = $DistUrl.TrimEnd('/')
    Write-Host "[2/8] Downloading binary: $base/bin/$asset"
    Invoke-WebRequest -Uri "$base/bin/$asset" -OutFile $TempPath
    Write-Host '[2/8] Downloading MIT license and third-party notices'
    foreach ($name in @('LICENSE', 'THIRD_PARTY_NOTICES')) {
        Invoke-WebRequest -Uri "$base/$name" -OutFile (Join-Path $TempDir $name)
    }
    $sumsPath = Join-Path $TempDir 'sha256sums.txt'
    Write-Host '[3/8] Downloading checksums and verifying SHA-256'
    Invoke-WebRequest -Uri "$base/sha256sums.txt" -OutFile $sumsPath
    $sumLine = Get-Content $sumsPath | Where-Object { $_ -match "\s+$([regex]::Escape($asset))$" } | Select-Object -First 1
    if (-not $sumLine -or $sumLine -notmatch '^([0-9a-fA-F]{64})\s+') { throw "No valid SHA-256 entry for $asset in sha256sums.txt." }
    $expectedHash = $Matches[1].ToLowerInvariant()
    $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $TempPath).Hash.ToLowerInvariant()
    if ($actualHash -ne $expectedHash) { throw 'Downloaded binary SHA-256 does not match the release checksum.' }
    Write-Host '[4/8] Detecting existing services and configuration'
    & $TempPath version
    if ($LASTEXITCODE -ne 0) { throw 'Downloaded binary could not run.' }
    $EffectiveConfig = if ($LegacyConfig) { $LegacyConfig } else { Join-Path $NewData 'config.yaml' }
    # Questions are asked by the verified binary before anything is stopped or
    # changed; the answers are applied in step 7.
    $AnswersPath = Join-Path $TempDir 'answers.yaml'
    $setupArgs = @('--config', $EffectiveConfig, 'setup', "--save-answers=$AnswersPath")
    foreach ($choice in @(
            @('NETRISER_OBSERVATION_MODE', '--observation-mode'),
            @('NETRISER_AUTO_UPDATE', '--auto-update'),
            @('NETRISER_ENABLE_REBOOT', '--enable-reboot'),
            @('NETRISER_ALLOW_VPN_BYPASS', '--allow-vpn-bypass'))) {
        $value = Normalize-Choice $choice[0] ([Environment]::GetEnvironmentVariable($choice[0]))
        if ($value) { $setupArgs += "$($choice[1])=$value" }
    }
    if ($env:NETRISER_NONINTERACTIVE -eq '1' -or -not [Environment]::UserInteractive -or [Console]::IsInputRedirected) {
        Write-Host 'No interactive console: new installations start in observation mode; existing settings are kept unless NETRISER_* variables select them.'
        $setupArgs += '--non-interactive'
    } else {
        Write-Host 'Installation questions (answer them again at any time with: nr setup)'
    }
    & $TempPath @setupArgs
    if ($LASTEXITCODE -ne 0) { throw 'Setup was cancelled or failed; nothing was changed.' }

    $Backup = Join-Path $ProgramData "NetRiser-Backups\migration-$([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'))-$([guid]::NewGuid().ToString('N'))"
    Write-Host "[5/8] Saving rollback backup: $Backup"
    New-Item -ItemType Directory -Path $Backup -Force | Out-Null
    foreach ($path in @($LicenseDir, $BinPath, (Join-Path $BinDir 'nr.cmd'), (Join-Path $BinDir 'mesh-watchdog.cmd'), $LegacyPath, $NewData, $LegacyData, $LegacyConfig)) { Copy-BackupPath $path }
    if ($LegacyService) { & reg.exe export 'HKLM\SYSTEM\CurrentControlSet\Services\mesh-watchdog' (Join-Path $Backup 'legacy-service.reg') /y | Out-Null }
    if ($NewService) { & reg.exe export 'HKLM\SYSTEM\CurrentControlSet\Services\netriser' (Join-Path $Backup 'netriser-service.reg') /y | Out-Null }

    New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
    $Mutating = $true
    Write-Host '[6/8] Stopping existing daemon and installing verified binary'
    if ($NewWasRunning) { Stop-Service netriser -Force }
    if ($LegacyWasRunning) { Stop-Service mesh-watchdog -Force }
    if ($LegacyService) { Set-Service mesh-watchdog -StartupType Disabled }

    Copy-Item -LiteralPath $TempPath -Destination $StagePath -Force
    if (Test-Path -LiteralPath $BinPath) {
        # Windows PowerShell converts $null to "" for .NET string arguments;
        # File.Replace rejects "" as a backup path. Pass a real null instead.
        [System.IO.File]::Replace($StagePath, $BinPath, [NullString]::Value, $true)
    } else {
        Move-Item -LiteralPath $StagePath -Destination $BinPath
    }
    New-Item -ItemType Directory -Path $LicenseDir -Force | Out-Null
    foreach ($name in @('LICENSE', 'THIRD_PARTY_NOTICES')) {
        Copy-Item -LiteralPath (Join-Path $TempDir $name) -Destination (Join-Path $LicenseDir $name) -Force
    }

    if ($LegacyConfig) {
        & $BinPath --config $LegacyConfig migrate
    } else {
        & $BinPath migrate
    }
    if ($LASTEXITCODE -ne 0) { throw "Configuration migration failed (exit $LASTEXITCODE)." }

    Write-Host "[7/8] Creating or preserving configuration: $EffectiveConfig"
    & $BinPath --config $EffectiveConfig setup "--answers=$AnswersPath" --no-restart
    if ($LASTEXITCODE -ne 0) { throw "Configuration update failed (exit $LASTEXITCODE)." }

    Write-Host '[8/8] Starting NetRiser and verifying service state'
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
    Write-Host "License: MIT; license texts installed in $LicenseDir"
    Write-Host 'Commands: nr status; nr setup (answer the installation questions again); nr observe on|off|status; nr autoupdate on|off|status; nr reboot on|off|status'
    if ((& $BinPath --config $EffectiveConfig observe status) -match 'Observation mode: ON') {
        Write-Host 'NetRiser is in observation mode: it records incidents but changes nothing. Enable recovery with: nr observe off'
    }
    Write-Host 'Logs: see "Log file" above (also shown by: nr check-config)'
} catch {
    Rollback-Install
    throw
} finally {
    Remove-Item -LiteralPath $StagePath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $TempDir -Recurse -Force -ErrorAction SilentlyContinue
}
