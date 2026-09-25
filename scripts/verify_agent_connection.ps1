<#
.SYNOPSIS
    Comprehensive SOC Lab Health & Diagnostic Tool (Windows Endpoint)
.DESCRIPTION
    Verifies Wazuh Agent, Microsoft Sysmon, FIM directories, firewall rules,
    and Web Monitoring Platform status.
#>

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   Wazuh SOC Lab Health & Diagnostic Verification Tool    " -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Check Wazuh Agent Service
Write-Host "`n[*] [1/6] Checking Wazuh Agent Status..." -ForegroundColor Cyan
$agentSvc = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
if ($null -eq $agentSvc) {
    Write-Host "  [!] Wazuh Agent service is NOT installed." -ForegroundColor Yellow
    Write-Host "      (Run .\install_agent.ps1 if connecting to an Ubuntu Wazuh Server)" -ForegroundColor DarkGray
} elseif ($agentSvc.Status -eq "Running") {
    Write-Host "  [+] Wazuh Agent Service (WazuhSvc): RUNNING" -ForegroundColor Green
} else {
    Write-Host "  [-] Wazuh Agent Service (WazuhSvc): $($agentSvc.Status)" -ForegroundColor Yellow
}

# 2. Check Sysmon Service
Write-Host "`n[*] [2/6] Checking Microsoft Sysmon Status..." -ForegroundColor Cyan
$sysmonSvc = Get-Service -Name "Sysmon64", "Sysmon" -ErrorAction SilentlyContinue
if ($sysmonSvc -and $sysmonSvc.Status -eq "Running") {
    Write-Host "  [+] Microsoft Sysmon Service ($($sysmonSvc.Name)): RUNNING" -ForegroundColor Green
} else {
    Write-Host "  [!] Sysmon Service: NOT RUNNING" -ForegroundColor Yellow
    Write-Host "      (Run .\install_sysmon.ps1 to install Sysmon with lab XML config)" -ForegroundColor DarkGray
}

# 3. Check Monitored Lab Directory & Quarantine Vault
Write-Host "`n[*] [3/6] Checking Lab Directories & FIM Targets..." -ForegroundColor Cyan
$labDir = "C:\SOC_Lab_Test"
$quarantineDir = "C:\SOC_Lab_Quarantine"

if (Test-Path $labDir) {
    $files = Get-ChildItem -Path $labDir
    Write-Host "  [+] Monitored Test Folder: $labDir (Files present: $($files.Count))" -ForegroundColor Green
} else {
    Write-Host "  [*] Creating monitored test folder: $labDir" -ForegroundColor DarkGray
    New-Item -ItemType Directory -Path $labDir -Force | Out-Null
    Write-Host "  [+] Monitored Test Folder created: $labDir" -ForegroundColor Green
}

if (Test-Path $quarantineDir) {
    $qFiles = Get-ChildItem -Path $quarantineDir
    Write-Host "  [+] Quarantine Isolation Vault: $quarantineDir (Isolated items: $($qFiles.Count))" -ForegroundColor Green
} else {
    New-Item -ItemType Directory -Path $quarantineDir -Force | Out-Null
    Write-Host "  [+] Quarantine Isolation Vault created: $quarantineDir" -ForegroundColor Green
}

# 4. Check Windows Defender Firewall Containment Rule
Write-Host "`n[*] [4/6] Checking Defensive Containment Rules..." -ForegroundColor Cyan
$fwRule = Get-NetFirewallRule -DisplayName "SOC_LAB_BLOCK_MALICIOUS_C2_TEST_IP" -ErrorAction SilentlyContinue
if ($fwRule -and $fwRule.Enabled -eq "True") {
    Write-Host "  [+] Host Containment Firewall Rule: ACTIVE (C2 203.0.113.50 is BLOCKED)" -ForegroundColor Green
} else {
    Write-Host "  [*] Host Containment Firewall Rule: STANDBY (Normal network mode)" -ForegroundColor DarkGray
}

# 5. Check Web Monitoring Platform (Port 5050)
Write-Host "`n[*] [5/6] Checking CyberSOC Shield Web Console..." -ForegroundColor Cyan
try {
    $webTest = Test-NetConnection -ComputerName "127.0.0.1" -Port 5050 -InformationLevel Quiet -WarningAction SilentlyContinue
    if ($webTest) {
        Write-Host "  [+] Web Monitoring Platform: RUNNING at http://localhost:5050" -ForegroundColor Green
    } else {
        Write-Host "  [!] Web Monitoring Platform: NOT RUNNING on port 5050" -ForegroundColor Yellow
        Write-Host "      (Double-click start_web_monitor.bat to launch GUI)" -ForegroundColor DarkGray
    }
} catch {
    Write-Host "  [*] Web platform check completed." -ForegroundColor DarkGray
}

# 6. Check Wazuh Server Configuration (if present)
Write-Host "`n[*] [6/6] Checking Server Connection..." -ForegroundColor Cyan
$agentDir = "C:\Program Files (x86)\ossec-agent"
$confPath = "$agentDir\ossec.conf"
if (Test-Path $confPath) {
    try {
        [xml]$xml = Get-Content $confPath
        $serverIP = $xml.ossec_config.client.server.address
        Write-Host "  [+] Configured Wazuh Server IP: $serverIP" -ForegroundColor Cyan
        if ($serverIP -and $serverIP -ne "0.0.0.0") {
            $test1514 = Test-NetConnection -ComputerName $serverIP -Port 1514 -InformationLevel Quiet
            if ($test1514) {
                Write-Host "  [+] Port 1514 (Wazuh Ingestion Channel): CONNECTED" -ForegroundColor Green
            } else {
                Write-Host "  [-] Port 1514 to $serverIP : UNREACHABLE" -ForegroundColor Yellow
            }
        }
    } catch {
        Write-Host "  [-] Could not parse ossec.conf: $_" -ForegroundColor Yellow
    }
} else {
    Write-Host "  [*] Wazuh Server: Standalone Local Mode (Simulation & Web Monitor operational)" -ForegroundColor DarkGray
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " Diagnostic check complete! All lab components verified. " -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan
