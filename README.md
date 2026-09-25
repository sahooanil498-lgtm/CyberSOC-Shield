# IOC / Security Alert Detection & Investigation
### Solo College Cybersecurity SOC Lab with Wazuh SIEM & CyberSOC Shield

---

## 📌 Project Overview
This project simulates an enterprise-grade **Security Operations Center (SOC)** detection, investigation, and incident response platform. It demonstrates:
- Centralized log ingestion and telemetry enrichment from an endpoint using **Microsoft Sysmon**.
- Real-Time File Integrity Monitoring (FIM) over critical assets.
- Threat detection using custom Wazuh SIEM correlation rules and Indicators of Compromise (IOC lists).
- An interactive **CyberSOC Shield** web-based monitoring console displaying live laptop telemetry, active intrusions, forensic alert inspection, and automated containment.
- Structured oral exam viva defense documentation and college presentation slide deck.

---

## 📁 Repository Structure
```
d:/Cyber project/
│
├── web/                       # CyberSOC Shield Web Monitoring Platform (GUI)
│   ├── server.py              # Multi-threaded Python Telemetry & API Server
│   ├── index.html             # High-End Dark Cyber Glassmorphism SOC Interface
│   ├── styles.css             # Vanilla CSS Responsive Design System
│   └── app.js                 # Real-Time Telemetry & Attack Simulation Engine
│
├── docs/                      # Phase-by-phase implementation & defense guides
│   ├── 01_Phase1_Project_Setup.md
│   ├── 02_Phase2_Lab_Installation.md
│   ├── 03_Phase3_Endpoint_Monitoring.md
│   ├── 04_Phase4_IOC_Detection.md
│   ├── 05_Phase5_Alert_Investigation.md
│   ├── 06_Phase6_Incident_Response.md
│   ├── 07_Phase7_Dashboard_Visualizations.md
│   ├── 08_Phase8_Project_Evidence.md
│   ├── 09_Phase9_Testing_Cases.md
│   ├── 10_Phase10_College_Documentation.md
│   ├── 11_Phase11_Presentation_Guide.md
│   └── 12_Phase12_Viva_Questions_Answers.md  👈 [Academic Oral Exam Prep Guide]
│
├── rules/                     # Custom Wazuh detection rules (XML)
│   └── local_rules.xml        # Rules 100001–100006 mapped to MITRE ATT&CK
│
├── iocs/                      # Threat intelligence & IOC CDB lists
│   └── test_iocs.txt          # Blacklisted hashes, test IPs, and file indicators
│
├── scripts/                   # Safe simulation scripts (PowerShell / Bash)
│   ├── simulate_fim.ps1
│   ├── simulate_ioc_event.ps1
│   ├── simulate_auth_event.ps1
│   ├── containment_simulation.ps1
│   └── verify_agent_connection.ps1
│
├── evidence/                  # Screenshots and log dumps for college submission
│
└── report/                    # Final college project documentation & PPT slides
    └── college_project_presentation_slides.md
```

---

## 🚀 How to Run the Project

### 🌟 Option 1: Web-Based SOC Monitoring Platform (GUI - Recommended)
Double-click **`start_web_monitor.bat`** in the project root folder.  
It automatically launches the telemetry engine in the background and opens your browser directly to:  
👉 **`http://localhost:5050`**

From this web console, you can:
- **Live SOC Monitor:** View real-time RAM usage, top monitored processes, sensor health tags, and active alerts.
- **Attack Simulator Lab:** Trigger benign, non-destructive test attacks (C2 socket, dropper, ransomware note, Base64 PowerShell, brute-force login) with live terminal output.
- **How It Protects You:** Explore the interactive 4-layer defense pipeline and comparative antivirus analysis.
- **SIEM Rules & IOCs:** Inspect all custom detection rules and active threat indicators.
- **Export SOC Dossier:** Download an automated JSON forensic incident dossier with a single click.

### Option 2: One-Click Interactive Terminal Launcher
Double-click **`run_project.bat`** in the project root folder to launch the interactive terminal menu (Options 1–12).

### Option 3: PowerShell Console
Open PowerShell and run:
```powershell
powershell -ExecutionPolicy Bypass -File "d:\Cyber project\run_project.ps1"
```

### Option 4: Run Individual Safe Threat Simulations
- **Threat Indicators & C2 Simulation (TC-01, TC-02, TC-04):**
  ```powershell
  powershell -ExecutionPolicy Bypass -File "d:\Cyber project\scripts\simulate_ioc_event.ps1"
  ```
- **Brute-Force Authentication Simulation (TC-03):**
  ```powershell
  powershell -ExecutionPolicy Bypass -File "d:\Cyber project\scripts\simulate_auth_event.ps1"
  ```
- **Incident Response Containment & Quarantine:**
  ```powershell
  powershell -ExecutionPolicy Bypass -File "d:\Cyber project\scripts\containment_simulation.ps1"
  ```

---

## 🛡️ Summary of Detection Rules
| Rule ID | Severity | MITRE ATT&CK | Trigger Mechanism | Indicator / Description |
| :---: | :---: | :---: | :---: | :--- |
| **100001** | Level 12 (Critical) | T1071.001 | Sysmon Event ID 3 | Outbound connection to Malicious C2 Test IP (`203.0.113.50:443`) |
| **100002** | Level 13 (Critical) | T1204.002 | Sysmon Event ID 1 | Execution of Process with Malicious IOC SHA256 Hash |
| **100003** | Level 10 (High) | T1105 | Sysmon Event ID 11 | Dropper executable created (`invoice_malware_sim.exe`) |
| **100004** | Level 11 (High) | T1486 | Wazuh FIM (Rule 554) | Ransomware extortion note dropped (`test_ransom_note.txt`) |
| **100005** | Level 8 (Medium) | T1059.001 | Sysmon Event ID 1 | Obfuscated Base64 PowerShell execution (`-EncodedCommand`) |
| **100006** | Level 10 (High) | T1110 | Windows Security 4625 | Brute-force authentication (3+ failed logins in 60s) |

---
*Created as part of the Defensive Cybersecurity & SOC Detection Lab.*
