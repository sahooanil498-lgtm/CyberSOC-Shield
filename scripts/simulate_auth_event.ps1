<#
.SYNOPSIS
    Safe Authentication / Brute-Force Event Simulation (College SOC Lab)
.DESCRIPTION
    Generates 4 controlled, harmless failed logon attempts against a dummy account
    to test Wazuh frequency-based correlation Rule 100006 (Brute Force Alert).
    100% SAFE: Does NOT lock out your active administrator account.
    Run in PowerShell as Administrator.
#>

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   SAFE SOC LAB: Authentication Event Simulator           " -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan

$dummyUser = "lab_test_intruder"
$wrongPassword = "IncorrectPassword999!"

Write-Host "`n[*] Simulating 4 rapid failed login attempts for dummy user '$dummyUser'..." -ForegroundColor Cyan
Write-Host "    Expected Alert: Rule 100006 [HIGH] Potential Brute-Force authentication attack (3+ fails in 60s)" -ForegroundColor DarkGray

# Load .NET logon validation assembly
Add-Type -AssemblyName System.DirectoryServices.AccountManagement

$context = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine)

for ($i = 1; $i -le 4; $i++) {
    Write-Host "  -> Attempt #$i - Testing bad credentials..." -ForegroundColor Yellow
    # ValidateCredentials with false password generates Windows Event ID 4625 without locking real accounts
    [void]$context.ValidateCredentials($dummyUser, $wrongPassword)
    Start-Sleep -Milliseconds 800
}

Write-Host "`n[+] 4 Failed Logon events (Event ID 4625) recorded in Windows Security Log!" -ForegroundColor Green
Write-Host "[*] Check Wazuh Dashboard: Security events -> Filter: rule.id: 100006 or data.win.system.eventID: 4625" -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Cyan
