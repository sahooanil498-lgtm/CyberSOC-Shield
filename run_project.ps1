<#
.SYNOPSIS
    Master Runner & Demonstration Console for College SOC Lab (Wazuh SIEM)
.DESCRIPTION
    Interactive menu to execute threat simulations, incident response containment,
    agent verification, and documentation viewing.
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
param()

$host.UI.RawUI.WindowTitle = "Wazuh SOC Lab - Master Demonstration Console"

function Show-Header {
    try { Clear-Host } catch {}
    Write-Host "==================================================================" -ForegroundColor Cyan
    Write-Host "       WAZUH CYBERSECURITY SOC LAB: MASTER RUNNER CONSOLE         " -ForegroundColor Yellow
    Write-Host "      IOC Detection, Threat Hunting & Incident Investigation      " -ForegroundColor White
    Write-Host "==================================================================" -ForegroundColor Cyan
}

function WaitConsole {
    Write-Host "`nPress any key to return to main menu..." -ForegroundColor DarkGray
    try {
        if ([Environment]::UserInteractive) {
            $null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        } else {
            Start-Sleep -Milliseconds 500
        }
    } catch {
        Start-Sleep -Milliseconds 500
    }
}

$projectRoot = $PSScriptRoot
if (-not $projectRoot) {
    $projectRoot = "d:\Cyber project"
}

do {
    Show-Header
    Write-Host ""
    Write-Host " [1] " -NoNewline -ForegroundColor Green; Write-Host "Run Threat Simulation: C2, Dropper, Ransom Note, Encoded PS"
    Write-Host " [2] " -NoNewline -ForegroundColor Green; Write-Host "Run Auth Simulation: Brute-Force Authentication (Event 4625)"
    Write-Host " [3] " -NoNewline -ForegroundColor Green; Write-Host "Run Incident Response: Host Containment & Quarantine"
    Write-Host " [4] " -NoNewline -ForegroundColor Yellow; Write-Host "Run End-to-End Simulation Pipeline (Tests 1 -> 2 -> 3)"
    Write-Host "------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host " [5] " -NoNewline -ForegroundColor Cyan; Write-Host "Diagnostic: Verify Wazuh Agent & Sensor Connection"
    Write-Host " [6] " -NoNewline -ForegroundColor Cyan; Write-Host "Setup: Install / Update Microsoft Sysmon (Admin)"
    Write-Host " [7] " -NoNewline -ForegroundColor Cyan; Write-Host "Setup: Install Wazuh Agent & Enroll to Server (Admin)"
    Write-Host " [8] " -NoNewline -ForegroundColor Cyan; Write-Host "Setup: Configure Agent Sysmon & FIM Channels (Admin)"
    Write-Host "------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host " [9] " -NoNewline -ForegroundColor Magenta; Write-Host "View Incident Investigation Dossier"
    Write-Host " [10]" -NoNewline -ForegroundColor Magenta; Write-Host "View Project Final Report"
    Write-Host " [11]" -NoNewline -ForegroundColor Magenta; Write-Host "View Presentation Slides"
    Write-Host " [12]" -NoNewline -ForegroundColor Magenta; Write-Host "View Viva Voce Oral Exam Q&A Guide (Phase 12)"
    Write-Host "------------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host " [13]" -NoNewline -ForegroundColor Green; Write-Host "Launch CyberSOC Shield Web Platform (Browser GUI)"
    Write-Host " [0] " -NoNewline -ForegroundColor Red; Write-Host "Exit Console"
    Write-Host "==================================================================" -ForegroundColor Cyan

    $choice = Read-Host "Select an option (0-13)"
    if ($null -eq $choice -or $choice -eq "") {
        break
    }

    switch ($choice) {
        "1" {
            try { Clear-Host } catch {}
            & "$projectRoot\scripts\simulate_ioc_event.ps1"
            WaitConsole
        }
        "2" {
            try { Clear-Host } catch {}
            & "$projectRoot\scripts\simulate_auth_event.ps1"
            WaitConsole
        }
        "3" {
            try { Clear-Host } catch {}
            & "$projectRoot\scripts\containment_simulation.ps1"
            WaitConsole
        }
        "4" {
            try { Clear-Host } catch {}
            Write-Host "[*] Executing Step 1: Threat IOC Simulation..." -ForegroundColor Cyan
            & "$projectRoot\scripts\simulate_ioc_event.ps1"
            Start-Sleep -Seconds 2

            Write-Host "`n[*] Executing Step 2: Brute-Force Authentication Simulation..." -ForegroundColor Cyan
            & "$projectRoot\scripts\simulate_auth_event.ps1"
            Start-Sleep -Seconds 2

            Write-Host "`n[*] Executing Step 3: Incident Containment & Quarantine..." -ForegroundColor Cyan
            & "$projectRoot\scripts\containment_simulation.ps1"

            Write-Host "`n[+] Full End-to-End Simulation Completed Successfully!" -ForegroundColor Green
            WaitConsole
        }
        "5" {
            try { Clear-Host } catch {}
            & "$projectRoot\scripts\verify_agent_connection.ps1"
            WaitConsole
        }
        "6" {
            try { Clear-Host } catch {}
            & "$projectRoot\scripts\install_sysmon.ps1"
            WaitConsole
        }
        "7" {
            try { Clear-Host } catch {}
            & "$projectRoot\scripts\install_agent.ps1"
            WaitConsole
        }
        "8" {
            try { Clear-Host } catch {}
            & "$projectRoot\scripts\configure_wazuh_agent.ps1"
            WaitConsole
        }
        "9" {
            $path = "$projectRoot\report\incident_investigation_dossier.md"
            Start-Process notepad.exe -ArgumentList "`"$path`""
            Write-Host "[+] Opened Incident Investigation Dossier in Notepad." -ForegroundColor Green
            WaitConsole
        }
        "10" {
            $path = "$projectRoot\report\college_project_final_report.md"
            Start-Process notepad.exe -ArgumentList "`"$path`""
            Write-Host "[+] Opened Final Academic Report in Notepad." -ForegroundColor Green
            WaitConsole
        }
        "11" {
            $path = "$projectRoot\report\college_project_presentation_slides.md"
            Start-Process notepad.exe -ArgumentList "`"$path`""
            Write-Host "[+] Opened Presentation Slide Deck in Notepad." -ForegroundColor Green
            WaitConsole
        }
        "12" {
            $path = "$projectRoot\docs\12_Phase12_Viva_Questions_Answers.md"
            Start-Process notepad.exe -ArgumentList "`"$path`""
            Write-Host "[+] Opened Phase 12 Viva Voce Q&A Guide in Notepad." -ForegroundColor Green
            WaitConsole
        }
        "13" {
            try { Clear-Host } catch {}
            Write-Host "[*] Checking CyberSOC Shield Web Server..." -ForegroundColor Cyan
            $portTest = Test-NetConnection -ComputerName "127.0.0.1" -Port 5050 -InformationLevel Quiet -WarningAction SilentlyContinue
            if (-not $portTest) {
                Write-Host "[*] Starting background web server on port 5050..." -ForegroundColor Cyan
                Start-Process python.exe -ArgumentList "`"$projectRoot\web\server.py`"" -WindowStyle Hidden
                Start-Sleep -Seconds 2
            }
            Write-Host "[+] Launching CyberSOC Shield Web Monitoring Platform..." -ForegroundColor Green
            Start-Process "http://localhost:5050"
            Write-Host "[+] Opened browser to http://localhost:5050" -ForegroundColor Green
            WaitConsole
        }
        "0" {
            Write-Host "`nExiting Wazuh SOC Lab Console. Goodbye!" -ForegroundColor Cyan
            break
        }
        default {
            Write-Warning "Invalid option. Please enter a number between 0 and 13."
            Start-Sleep -Seconds 1
        }
    }
} while ($choice -ne "0")
