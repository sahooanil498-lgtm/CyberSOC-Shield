<#
.SYNOPSIS
    Automated Wazuh Agent Setup Script for Windows Endpoint (College SOC Lab)
.DESCRIPTION
    Downloads, installs, and connects the Wazuh Agent to your Ubuntu Wazuh Server.
    Run this script in PowerShell as Administrator.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$ManagerIP
)

# 1. Require Administrator Privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "[-] Administrator privileges required. Attempting to relaunch with elevation..."
    try {
        Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
        Exit 0
    } catch {
        Write-Error "CRITICAL: Please right-click PowerShell and choose 'Run as Administrator' to execute this script."
        Exit 1
    }
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Wazuh Agent Automated Setup (Windows Endpoint Lab)     " -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan

# 2. Get Manager IP if not provided
if (-not $ManagerIP) {
    $ManagerIP = Read-Host "Enter your Ubuntu Wazuh Server IP Address (e.g. 192.168.1.150)"
}

if ([string]::IsNullOrWhiteSpace($ManagerIP)) {
    Write-Error "Manager IP cannot be empty. Script aborted."
    Exit 1
}

# 3. Test Connectivity to Wazuh Port 1514
Write-Host "`n[*] Testing network connectivity to $ManagerIP on port 1514..." -ForegroundColor Cyan
$connTest = Test-NetConnection -ComputerName $ManagerIP -Port 1514 -InformationLevel Quiet
if ($connTest) {
    Write-Host "[+] Connection to Wazuh Server successful!" -ForegroundColor Green
} else {
    Write-Warning "[-] Could not reach $ManagerIP on port 1514."
    Write-Warning "    Ensure Ubuntu VM is running, firewall allows port 1514, and IP is correct."
    $proceed = Read-Host "Do you still want to continue installation? (y/n)"
    if ($proceed -ne 'y' -and $proceed -ne 'Y') {
        Exit 1
    }
}

# 4. Download Wazuh Agent MSI
$installerPath = "$env:TEMP\wazuh-agent-4.9.0.msi"
$agentUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.0-1.msi"

Write-Host "`n[*] Downloading official Wazuh Agent installer from: $agentUrl ..." -ForegroundColor Cyan
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $agentUrl -OutFile $installerPath -UseBasicParsing
    Write-Host "[+] Installer downloaded successfully to $installerPath" -ForegroundColor Green
} catch {
    Write-Error "[-] Failed to download installer: $_"
    Exit 1
}

# 5. Install and Enroll Agent
Write-Host "`n[*] Installing Wazuh Agent and enrolling to $ManagerIP..." -ForegroundColor Cyan
$agentName = "WIN-ENDPOINT-01"
$msiArgs = "/i `"$installerPath`" /q WAZUH_MANAGER=`"$ManagerIP`" WAZUH_REGISTRATION_SERVER=`"$ManagerIP`" WAZUH_AGENT_NAME=`"$agentName`""

$process = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru
if ($process.ExitCode -eq 0) {
    Write-Host "[+] Wazuh Agent installed successfully!" -ForegroundColor Green
} else {
    Write-Error "[-] Installation exited with error code $($process.ExitCode)."
    Exit 1
}

# 6. Start the Wazuh Service
Write-Host "`n[*] Starting Wazuh Windows Service (WazuhSvc)..." -ForegroundColor Cyan
Start-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3

$svc = Get-Service -Name "WazuhSvc"
if ($svc.Status -eq "Running") {
    Write-Host "[+] Wazuh Agent Service is RUNNING!" -ForegroundColor Green
} else {
    Write-Warning "[-] Service status is $($svc.Status). Attempting 'NET START WazuhSvc'..."
    cmd.exe /c "NET START WazuhSvc"
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " Setup Complete! Next verification steps:" -ForegroundColor Yellow
Write-Host " 1. Check Ubuntu Wazuh Manager: sudo /var/ossec/bin/agent_control -l" -ForegroundColor White
Write-Host " 2. Check Wazuh Dashboard: https://$ManagerIP (Look for $agentName)" -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Cyan
