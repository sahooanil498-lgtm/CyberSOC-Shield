<#
.SYNOPSIS
    Automated Sysmon Installation & Configuration Script for Windows Endpoint
.DESCRIPTION
    Downloads official Microsoft Sysinternals Sysmon, applies our SOC lab XML config,
    and starts the Sysmon service.
    Run in PowerShell as Administrator.
#>

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "[-] Administrator privileges required. Attempting to relaunch with elevation..."
    try {
        Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
        Exit 0
    } catch {
        Write-Error "[-] Administrator privileges required! Right-click PowerShell and select 'Run as Administrator'."
        Exit 1
    }
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "     Microsoft Sysmon Automated Setup (SOC Lab)           " -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan

$workDir = "$env:TEMP\SysmonInstall"
if (-not (Test-Path $workDir)) {
    New-Item -ItemType Directory -Path $workDir -Force | Out-Null
}

# 1. Download Sysmon zip from Microsoft Sysinternals
$sysmonZipUrl = "https://download.sysinternals.com/files/Sysmon.zip"
$zipPath = "$workDir\Sysmon.zip"

Write-Host "`n[*] Downloading Microsoft Sysmon from official Sysinternals..." -ForegroundColor Cyan
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $sysmonZipUrl -OutFile $zipPath -UseBasicParsing

# 2. Extract Sysmon
Write-Host "[*] Extracting Sysmon.zip..." -ForegroundColor Cyan
try {
    Expand-Archive -Path $zipPath -DestinationPath $workDir -Force
} catch {
    if (-not (Test-Path "$workDir\Sysmon64.exe")) {
        Write-Error "[-] Failed to extract Sysmon.zip: $_"
        Exit 1
    }
}

# 3. Locate Sysmon Config File
$configSource = if ($PSScriptRoot) {
    Join-Path $PSScriptRoot "..\configs\sysmonconfig.xml"
} else {
    "d:\Cyber project\configs\sysmonconfig.xml"
}
if (-not (Test-Path $configSource)) {
    $configSource = "d:\Cyber project\configs\sysmonconfig.xml"
}
$targetConfig = "$workDir\sysmonconfig.xml"

if (Test-Path $configSource) {
    Copy-Item -Path $configSource -Destination $targetConfig -Force
    Write-Host "[+] Loaded custom SOC lab Sysmon config from: $configSource" -ForegroundColor Green
} else {
    Write-Host "[*] Downloading community baseline Sysmon config..." -ForegroundColor Yellow
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile $targetConfig -UseBasicParsing
}

# 4. Install or Update Sysmon64.exe with Config
Write-Host "`n[*] Configuring Sysmon64 service..." -ForegroundColor Cyan
$installCmd = "$workDir\Sysmon64.exe"

$existingSvc = Get-Service -Name "Sysmon64", "Sysmon" -ErrorAction SilentlyContinue
if ($existingSvc) {
    Write-Host "[*] Sysmon service is already installed. Updating configuration..." -ForegroundColor Cyan
    $installArgs = "-accepteula -c `"$targetConfig`""
} else {
    Write-Host "[*] Installing new Sysmon64 service..." -ForegroundColor Cyan
    $installArgs = "-accepteula -i `"$targetConfig`""
}

Start-Process -FilePath $installCmd -ArgumentList $installArgs -Wait

# 5. Verify Sysmon Service
$sysmonSvc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
if ($null -eq $sysmonSvc) {
    $sysmonSvc = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue
}

if ($sysmonSvc -and $sysmonSvc.Status -eq "Running") {
    Write-Host "`n[+] SUCCESS: Sysmon Service is installed and RUNNING!" -ForegroundColor Green
    Write-Host "[+] Sysmon Event Log path: Applications and Services Logs > Microsoft > Windows > Sysmon > Operational" -ForegroundColor Green
} else {
    Write-Host "`n[-] Sysmon service installation needs verification. Service state: $($sysmonSvc.Status)" -ForegroundColor Red
}

Write-Host "==========================================================" -ForegroundColor Cyan
