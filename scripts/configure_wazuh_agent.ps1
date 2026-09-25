<#
.SYNOPSIS
    Automated Wazuh Agent Configuration for Sysmon Ingestion and FIM
.DESCRIPTION
    1. Creates test directory C:\SOC_Lab_Test
    2. Backs up C:\Program Files (x86)\ossec-agent\ossec.conf
    3. Injects Sysmon eventchannel and FIM real-time monitoring configuration
    4. Restarts WazuhSvc service
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
Write-Host "   Wazuh Agent Sysmon & FIM Auto-Configuration Tool       " -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Create Lab Directory
$labDir = "C:\SOC_Lab_Test"
if (-not (Test-Path $labDir)) {
    New-Item -ItemType Directory -Path $labDir -Force | Out-Null
    Write-Host "[+] Created FIM Lab Folder: $labDir" -ForegroundColor Green
} else {
    Write-Host "[*] FIM Lab Folder already exists: $labDir" -ForegroundColor Cyan
}

# 2. Locate ossec.conf
$confPath = "C:\Program Files (x86)\ossec-agent\ossec.conf"
if (-not (Test-Path $confPath)) {
    Write-Error "[-] ossec.conf not found at $confPath. Is Wazuh Agent installed?"
    Exit 1
}

# 3. Create Backup
$backupPath = "C:\Program Files (x86)\ossec-agent\ossec.conf.bak_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
Copy-Item -Path $confPath -Destination $backupPath -Force
Write-Host "[+] Backup created at: $backupPath" -ForegroundColor Green

# 4. Read and Update ossec.conf
[xml]$xml = Get-Content $confPath

# Check if Sysmon channel already exists
$sysmonExists = $false
foreach ($localfile in $xml.ossec_config.localfile) {
    if ($localfile.location -eq "Microsoft-Windows-Sysmon/Operational") {
        $sysmonExists = $true
        break
    }
}

if (-not $sysmonExists) {
    Write-Host "[*] Adding Sysmon event channel to ossec.conf..." -ForegroundColor Cyan
    $newElement = $xml.CreateElement("localfile")
    
    $loc = $xml.CreateElement("location")
    $loc.InnerText = "Microsoft-Windows-Sysmon/Operational"
    $newElement.AppendChild($loc) | Out-Null
    
    $fmt = $xml.CreateElement("log_format")
    $fmt.InnerText = "eventchannel"
    $newElement.AppendChild($fmt) | Out-Null
    
    $xml.ossec_config.AppendChild($newElement) | Out-Null
    Write-Host "[+] Sysmon eventchannel added successfully." -ForegroundColor Green
} else {
    Write-Host "[*] Sysmon eventchannel already present." -ForegroundColor Cyan
}

# Ensure FIM syscheck is enabled
if ($xml.ossec_config.syscheck.disabled -eq "yes") {
    $xml.ossec_config.syscheck.disabled = "no"
    Write-Host "[+] Enabled FIM syscheck (disabled set to 'no')." -ForegroundColor Green
}

# Check if FIM C:\SOC_Lab_Test directory is configured
$fimExists = $false
foreach ($dir in $xml.ossec_config.syscheck.directories) {
    if ($dir.InnerText -eq "C:\SOC_Lab_Test" -or $dir."#text" -eq "C:\SOC_Lab_Test") {
        $fimExists = $true
        break
    }
}

if (-not $fimExists) {
    Write-Host "[*] Adding C:\SOC_Lab_Test real-time FIM monitoring..." -ForegroundColor Cyan
    $newDir = $xml.CreateElement("directories")
    $newDir.SetAttribute("check_all", "yes")
    $newDir.SetAttribute("realtime", "yes")
    $newDir.SetAttribute("report_changes", "yes")
    $newDir.InnerText = "C:\SOC_Lab_Test"
    
    $xml.ossec_config.syscheck.AppendChild($newDir) | Out-Null
    Write-Host "[+] Real-time FIM directory added successfully." -ForegroundColor Green
} else {
    Write-Host "[*] Real-time FIM directory already configured." -ForegroundColor Cyan
}

# Save updated XML
$xml.Save($confPath)
Write-Host "[+] ossec.conf saved successfully!" -ForegroundColor Green

# 5. Restart Wazuh Agent Service
Write-Host "`n[*] Restarting Wazuh Agent Service (WazuhSvc)..." -ForegroundColor Cyan
Restart-Service -Name "WazuhSvc" -Force
Start-Sleep -Seconds 3

$svc = Get-Service -Name "WazuhSvc"
if ($svc.Status -eq "Running") {
    Write-Host "[+] Wazuh Agent is RUNNING with new Sysmon and FIM configuration!" -ForegroundColor Green
} else {
    Write-Warning "[-] Service status is $($svc.Status). Run 'NET START WazuhSvc' manually."
}

Write-Host "==========================================================" -ForegroundColor Cyan
