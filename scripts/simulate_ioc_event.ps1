<#
.SYNOPSIS
    Safe Threat & IOC Event Simulation Script (College SOC Lab)
.DESCRIPTION
    Simulates benign, controlled security anomalies to test custom Wazuh detection rules:
    - Test Case 1: Outbound test connection to C2 test IP (Rule 100001)
    - Test Case 2: Suspicious test dropper filename creation (Rule 100003)
    - Test Case 3: Simulated Ransom note dropped in FIM directory (Rule 100004 & Rule 550)
    - Test Case 4: Base64 Encoded benign PowerShell command (Rule 100005)
    100% SAFE: No destructive actions, no real malware, no external damage.
#>

param (
    [Parameter(Mandatory=$false)]
    [ValidateSet("All", "1", "2", "3", "4")]
    [string]$TestCase = "All"
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   SAFE SOC LAB: Security Event & IOC Simulator           " -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "NOTE: All actions are harmless educational simulations." -ForegroundColor Gray

$labDir = "C:\SOC_Lab_Test"
if (-not (Test-Path $labDir)) {
    New-Item -ItemType Directory -Path $labDir -Force | Out-Null
}

# -----------------------------------------------------------------------------
# TEST CASE 1: Outbound Connection to Malicious C2 Test IP (Rule 100001)
# -----------------------------------------------------------------------------
if ($TestCase -eq "All" -or $TestCase -eq "1") {
    Write-Host "`n[*] [TEST 1] Simulating C2 Connection to RFC Test IP 203.0.113.50..." -ForegroundColor Cyan
    Write-Host "    Expected Alert: Rule 100001 [CRITICAL] Outbound connection to Known Malicious C2 Test IP" -ForegroundColor DarkGray
    
    # We attempt a TCP handshake to the reserved test IP on port 443 (will safely timeout or fail, but Sysmon Event ID 3 will record the attempt!)
    $testJob = Start-Job -ScriptBlock {
        $client = New-Object System.Net.Sockets.TcpClient
        try {
            $client.ConnectAsync("203.0.113.50", 443).Wait(1500) | Out-Null
        } catch { }
        finally { $client.Close() }
    }
    Wait-Job $testJob -Timeout 3 | Out-Null
    Receive-Job $testJob | Out-Null
    Remove-Job $testJob -Force | Out-Null
    Write-Host "[+] Test 1 executed! Sysmon Event ID 3 recorded." -ForegroundColor Green
}

# -----------------------------------------------------------------------------
# TEST CASE 2: Suspicious File Dropper Created in Lab Folder (Rule 100003)
# -----------------------------------------------------------------------------
if ($TestCase -eq "All" -or $TestCase -eq "2") {
    Write-Host "`n[*] [TEST 2] Simulating Suspicious Payload Drop: invoice_malware_sim.exe..." -ForegroundColor Cyan
    Write-Host "    Expected Alert: Rule 100003 [MEDIUM] Suspicious test dropper created on disk" -ForegroundColor DarkGray

    $filePath = "$labDir\invoice_malware_sim.exe"
    # Harmless benign dummy text stored in the executable name
    "MZ_SIMULATED_TEST_PAYLOAD_FOR_COLLEGE_SOC_LAB" | Out-File -FilePath $filePath -Force
    Write-Host "[+] Test 2 executed! Created dummy test binary: $filePath" -ForegroundColor Green
}

# -----------------------------------------------------------------------------
# TEST CASE 3: Simulated Ransomware Note (Rule 100004 & FIM Rule 550)
# -----------------------------------------------------------------------------
if ($TestCase -eq "All" -or $TestCase -eq "3") {
    Write-Host "`n[*] [TEST 3] Simulating Ransomware Indicator: test_ransom_note.txt..." -ForegroundColor Cyan
    Write-Host "    Expected Alert: Rule 100004 [HIGH] Potential Ransomware Indicator & Rule 550 (FIM)" -ForegroundColor DarkGray

    $notePath = "$labDir\test_ransom_note.txt"
    $simulatedNoteContent = @"
=====================================================
!!! WARNING: THIS IS A BENIGN COLLEGE LAB SIMULATION !!!
All your files have been simulated as locked.
Contact test_lab_admin@college.local for SOC evaluation.
IOC Hash: 4a1b025fbc77660c6753a798a69eef52467d302a281898114f6d4d161d713c23
=====================================================
"@
    $simulatedNoteContent | Out-File -FilePath $notePath -Force
    Write-Host "[+] Test 3 executed! Dropped benign ransom note: $notePath" -ForegroundColor Green
}

# -----------------------------------------------------------------------------
# TEST CASE 4: Obfuscated Base64 Encoded PowerShell Command (Rule 100005)
# -----------------------------------------------------------------------------
if ($TestCase -eq "All" -or $TestCase -eq "4") {
    Write-Host "`n[*] [TEST 4] Simulating Encoded PowerShell Command Execution..." -ForegroundColor Cyan
    Write-Host "    Expected Alert: Rule 100005 [MEDIUM] Obfuscated or Base64 Encoded PowerShell command" -ForegroundColor DarkGray

    # Benign string: Write-Host 'SOC-Lab-Benign-Simulation-Testing'
    $benignCommand = "Write-Host 'SOC-Lab-Benign-Simulation-Testing'"
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($benignCommand)
    $encodedCommand = [Convert]::ToBase64String($bytes)

    # Launch harmless encoded command in background
    powershell.exe -NoProfile -NonInteractive -EncodedCommand $encodedCommand
    Write-Host "[+] Test 4 executed! Launched encoded command safely." -ForegroundColor Green
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " Simulation Finished! Check Wazuh Dashboard Security Events." -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan
