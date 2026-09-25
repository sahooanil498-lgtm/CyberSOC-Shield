<#
.SYNOPSIS
    Defensive Incident Response & Containment Script (Safe SOC Lab)
.DESCRIPTION
    Simulates defensive containment and recovery actions without harming the system:
    1. Quarantines suspicious test artifact (invoice_malware_sim.exe) to a safe quarantine folder
    2. Implements a host firewall block rule against malicious test IP (203.0.113.50)
    3. Runs an integrity check to verify lab cleanliness
    Run in PowerShell as Administrator.
#>

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   INCIDENT RESPONSE: Defensive Containment & Recovery    " -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan

if (-not $isAdmin) {
    Write-Host "[!] Notice: Running in Standard User session." -ForegroundColor Yellow
    Write-Host "    - File Quarantine & Cleanup actions will execute fully." -ForegroundColor DarkGray
    Write-Host "    - Host Firewall rule modification requires Administrator privileges." -ForegroundColor DarkGray
}

# -----------------------------------------------------------------------------
# STEP 1: Host-Level Network Containment (Block Malicious C2 IP)
# -----------------------------------------------------------------------------
$ruleName = "SOC_LAB_BLOCK_MALICIOUS_C2_TEST_IP"
$maliciousIP = "203.0.113.50"

Write-Host "`n[*] [STEP 1: NETWORK CONTAINMENT] Applying Host Firewall Policy..." -ForegroundColor Cyan

if ($isAdmin) {
    try {
        Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName $ruleName `
            -Direction Outbound `
            -Action Block `
            -RemoteAddress $maliciousIP `
            -Protocol TCP `
            -Description "Automated SOC Containment: Block known C2 test indicator $maliciousIP" `
            -ErrorAction Stop | Out-Null
        Write-Host "[+] Host Firewall Rule applied: Outbound traffic to $maliciousIP is BLOCKED!" -ForegroundColor Green
    } catch {
        Write-Warning "[-] Could not add host firewall rule: $($_.Exception.Message)"
    }
} else {
    Write-Host "[-] Firewall Rule skipped (Requires Admin). Run PowerShell as Administrator for live firewall isolation." -ForegroundColor Yellow
}

# -----------------------------------------------------------------------------
# STEP 2: Artifact Quarantine
# -----------------------------------------------------------------------------
$labDir = "C:\SOC_Lab_Test"
$quarantineDir = "C:\SOC_Lab_Quarantine"
$threatFile = "$labDir\invoice_malware_sim.exe"

Write-Host "`n[*] [CONTAINMENT] Checking for active threat artifacts to quarantine..." -ForegroundColor Cyan

if (-not (Test-Path $quarantineDir)) {
    New-Item -ItemType Directory -Path $quarantineDir -Force | Out-Null
}

if (Test-Path $threatFile) {
    # Move to quarantine with safe extension
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $quarantineDest = "$quarantineDir\invoice_malware_sim.exe.quarantined_$timestamp"
    Move-Item -Path $threatFile -Destination $quarantineDest -Force
    Write-Host "[+] Artifact neutralized and moved to: $quarantineDest" -ForegroundColor Green
} else {
    Write-Host "[*] Threat file was already removed or not present: $threatFile" -ForegroundColor Cyan
}

# -----------------------------------------------------------------------------
# STEP 3: Recovery & Cleanup of Benign Simulation Artifacts
# -----------------------------------------------------------------------------
Write-Host "`n[*] [RECOVERY] Restoring endpoint to clean state..." -ForegroundColor Cyan

$noteFile = Join-Path $labDir "test_ransom_note.txt"
if (Test-Path $noteFile) {
    Remove-Item -Path $noteFile -Force
    Write-Host "[+] Removed simulated ransom note: $noteFile" -ForegroundColor Green
}

# -----------------------------------------------------------------------------
# STEP 4: Post-Incident Integrity Verification
# -----------------------------------------------------------------------------
Write-Host "`n[*] [VERIFICATION] Verifying lab folder integrity..." -ForegroundColor Cyan
$remainingFiles = Get-ChildItem -Path $labDir
Write-Host "[+] Active files remaining in directory: $($remainingFiles.Count)" -ForegroundColor Green

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " Containment & Remediation Actions Completed Successfully!" -ForegroundColor Yellow
Write-Host " Document these actions in your Incident Response Report. " -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Cyan
