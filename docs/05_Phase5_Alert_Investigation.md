# PHASE 5: Security Alert Investigation & Triage Dossier

---

## 1. Overview of Phase 5
Once security alerts fire in a SIEM, the primary duty of a SOC Analyst is **Alert Triage and Deep Investigation**.
An analyst must determine:
- Is this a **True Positive (TP)** or a **False Positive (FP)**?
- What was the **root cause** and **entry point**?
- What systems, files, or user accounts are compromised?
- What evidence exists across the event timeline?

This document breaks down the **formal investigation** of our 4 lab test alerts using standard SOC triage methodology.

---

## 2. Investigation Case 1: Outbound C2 Network Beaconing

### Alert Metadata:
| Field | Value |
| :--- | :--- |
| **Alert ID** | `SOC-ALT-2026-001` |
| **Timestamp** | `2026-09-25T10:35:12.431Z` |
| **Source Host** | `WIN-ENDPOINT-01` (Agent ID: `001`, IP: `192.168.1.151`) |
| **Event Source** | Microsoft Sysmon (Provider: `Microsoft-Windows-Sysmon/Operational`) |
| **Event Type** | **Event ID 3 (Network Connection)** |
| **Rule ID** | **`100001`** |
| **Alert Level / Severity** | **Level 12 (Critical)** |
| **MITRE ATT&CK** | `T1071.001` — Command and Control: Web Protocols |
| **Indicator of Compromise (IOC)** | **`203.0.113.50:443`** (Designated Threat Intel C2 IP) |

### Why the Alert Was Triggered:
Wazuh rule `100001` monitored Sysmon Event ID 3 for outbound TCP socket connections. The field `win.eventdata.destinationIp` matched an active IOC in our threat list (`203.0.113.50`).

### Evidence Available in Logs:
```json
{
  "timestamp": "2026-09-25T10:35:12.431Z",
  "rule": {
    "id": "100001",
    "level": 12,
    "description": "SOC-LAB ALERT [CRITICAL]: Outbound network connection to Known Malicious C2 Test IP (203.0.113.50) by process C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe."
  },
  "agent": {
    "id": "001",
    "name": "WIN-ENDPOINT-01",
    "ip": "192.168.1.151"
  },
  "data": {
    "win": {
      "system": {
        "eventID": "3",
        "providerName": "Microsoft-Windows-Sysmon"
      },
      "eventdata": {
        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "processId": "4892",
        "user": "WIN-ENDPOINT-01\\socadmin",
        "protocol": "tcp",
        "sourceIp": "192.168.1.151",
        "sourcePort": "52814",
        "destinationIp": "203.0.113.50",
        "destinationPort": "443"
      }
    }
  }
}
```

### Investigation Steps:
1. **Validate Destination:** Queried threat intelligence database. Destination IP `203.0.113.50` is a flagged malicious C2 infrastructure node.
2. **Process Attribution:** Identified initiating process as `powershell.exe` running under user `socadmin`. Standard user processes should not initiate direct outbound raw socket connections to unknown external IPs.
3. **Correlate Process Tree:** Searched Sysmon Event ID 1 around the same timestamp (`±30s`) to identify who launched `powershell.exe`. Found parent process `simulate_ioc_event.ps1`.
4. **Scope Verification:** Checked if other endpoints connected to `203.0.113.50`. Result: 0 other connections.

### Final Conclusion:
**True Positive (Simulated Threat).** Endpoint `WIN-ENDPOINT-01` attempted communication with an external malicious C2 server. 
*Recommended action:* Isolate host network interface and inspect executing scripts.

---

## 3. Investigation Case 2: Suspicious Dropper File Creation

### Alert Metadata:
| Field | Value |
| :--- | :--- |
| **Alert ID** | `SOC-ALT-2026-002` |
| **Timestamp** | `2026-09-25T10:35:13.112Z` |
| **Source Host** | `WIN-ENDPOINT-01` |
| **Event Source** | Microsoft Sysmon |
| **Event Type** | **Event ID 11 (File Create)** |
| **Rule ID** | **`100003`** |
| **Alert Level / Severity** | **Level 10 (High)** |
| **MITRE ATT&CK** | `T1105` — Ingress Tool Transfer |
| **Indicator of Compromise (IOC)** | Filename: **`invoice_malware_sim.exe`** |

### Why the Alert Was Triggered:
Sysmon detected the creation of an executable file inside `C:\SOC_Lab_Test\` matching our suspicious naming regex filter (`invoice_malware_sim.exe`). This is a classic social engineering / fake invoice phishing pattern.

### Evidence Available in Logs:
- `data.win.eventdata.targetFilename`: `C:\SOC_Lab_Test\invoice_malware_sim.exe`
- `data.win.eventdata.image`: `powershell.exe`
- `data.win.eventdata.user`: `WIN-ENDPOINT-01\socadmin`
- `data.win.eventdata.creationUtcTime`: `2026-09-25 10:35:13.090`

### Investigation Steps:
1. **File Inspection:** Verified file location: `C:\SOC_Lab_Test\invoice_malware_sim.exe`.
2. **Hash Computation:** Ran `Get-FileHash -Algorithm SHA256 "C:\SOC_Lab_Test\invoice_malware_sim.exe"` to calculate artifact signature.
3. **Execution Check:** Queried Sysmon Event ID 1 to verify if `invoice_malware_sim.exe` had been executed. Found: No execution record yet (file was only dropped).
4. **Origin Tracing:** Traced creation to PowerShell session invoked by user `socadmin`.

### Final Conclusion:
**True Positive (Simulated Ingress Payload).** A suspicious binary was introduced onto the file system, likely representing an initial stager. 
*Recommended action:* Quarantine the file immediately before user execution.

---

## 4. Investigation Case 3: Ransomware Note Dropped & FIM Alert

### Alert Metadata:
| Field | Value |
| :--- | :--- |
| **Alert ID** | `SOC-ALT-2026-003` |
| **Timestamp** | `2026-09-25T10:35:14.020Z` |
| **Source Host** | `WIN-ENDPOINT-01` |
| **Event Source** | Wazuh File Integrity Monitoring (`syscheck`) |
| **Event Type** | **FIM File Added / Content Signature Match** |
| **Rule ID** | **`100004`** (Inherits Rule `550`) |
| **Alert Level / Severity** | **Level 11 (High)** |
| **MITRE ATT&CK** | `T1486` — Data Encrypted for Impact |
| **Indicator of Compromise (IOC)** | Filename: `test_ransom_note.txt` + IOC SHA256 Hash |

### Why the Alert Was Triggered:
Wazuh's real-time FIM engine detected the sudden creation of a text file titled `test_ransom_note.txt` containing ransomware extortion verbiage inside monitored path `C:\SOC_Lab_Test\`.

### Evidence Available in Logs:
- `syscheck.path`: `C:\SOC_Lab_Test\test_ransom_note.txt`
- `syscheck.event`: `added`
- `syscheck.sha256_after`: `4a1b025fbc77660c6753a798a69eef52467d302a281898114f6d4d161d713c23`
- `syscheck.size_after`: `294 bytes`

### Investigation Steps:
1. **Analyze File Content:** Reviewed file text. The file demands contact for decryption, characteristic of Ransomware Impact stage.
2. **Mass Modification Check:** Inspected FIM event frequency in the last 5 minutes. No mass file modifications or file extension changes (`.locked` or `.crypto`) were found, confirming attack was simulated/halted.
3. **Volume Shadow Copy Verification:** Ran `vssadmin list shadows` on endpoint to ensure shadow copies were not destroyed.

### Final Conclusion:
**True Positive (Simulated Ransomware Impact).** Ransom note indicator identified in critical directory.
*Recommended action:* Immediately isolate endpoint, verify integrity of backups and shadow copies.

---

## 5. Investigation Case 4: Base64 Obfuscated PowerShell Execution

### Alert Metadata:
| Field | Value |
| :--- | :--- |
| **Alert ID** | `SOC-ALT-2026-004` |
| **Timestamp** | `2026-09-25T10:35:15.550Z` |
| **Source Host** | `WIN-ENDPOINT-01` |
| **Event Source** | Microsoft Sysmon |
| **Event Type** | **Event ID 1 (Process Create)** |
| **Rule ID** | **`100005`** |
| **Alert Level / Severity** | **Level 8 (Medium)** |
| **MITRE ATT&CK** | `T1059.001` — Command & Scripting Interpreter: PowerShell |
| **Indicator of Compromise (IOC)** | Command-line argument: `-EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAg...` |

### Why the Alert Was Triggered:
Sysmon Event ID 1 captured process `powershell.exe` invoked with the `-EncodedCommand` flag. Attackers routinely use Base64 encoding to bypass plain-text command logging and EDR signature inspection.

### Evidence Available in Logs:
- `data.win.eventdata.image`: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- `data.win.eventdata.commandLine`: `powershell.exe -NoProfile -NonInteractive -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACcAUwBPAEMALQBMAGEAYgAtAEIAZQBuAGkAZwBuAC0AUwBpAG0AdQBsAGEAdABpAG8AbgAtAFQAZQBzAHQAaQBuAGcAJwA=`
- `data.win.eventdata.parentImage`: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- `data.win.eventdata.hashes`: `SHA256=DE96A6E699...`

### Investigation Steps:
1. **De-obfuscate Payload:** Extracted Base64 string and decoded via CyberChef / PowerShell:
   ```powershell
   [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("VwByAGkAdABlAC0ASABvAHMAdAAgACcAUwBPAEMALQBMAGEAYgAtAEIAZQBuAGkAZwBuAC0AUwBpAG0AdQBsAGEAdABpAG8AbgAtAFQAZQBzAHQAaQBuAGcAJwA="))
   ```
2. **Evaluate Decoded Intent:** Decoded string yielded: `Write-Host 'SOC-Lab-Benign-Simulation-Testing'`.
3. **Intent Determination:** While the encoding technique is suspicious and high-risk, the payload itself is benign educational simulation.

### Final Conclusion:
**True Positive (Technique Detection / Benign Payload).** Confirms SIEM ability to intercept evasive PowerShell command lines regardless of encoding.

---

## 6. Summary Comparison Table for College Project Report

| Alert ID | Rule ID | Threat Type | MITRE ID | Severity | Evidence Artifact | Classification |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **SOC-ALT-2026-001** | `100001` | C2 Network Connection | `T1071.001` | Critical (12) | Outbound connection to `203.0.113.50:443` | True Positive (Simulated) |
| **SOC-ALT-2026-002** | `100003` | Ingress Payload Dropper | `T1105` | High (10) | Created `invoice_malware_sim.exe` | True Positive (Simulated) |
| **SOC-ALT-2026-003** | `100004` | Ransomware Indicator | `T1486` | High (11) | Dropped `test_ransom_note.txt` + SHA256 | True Positive (Simulated) |
| **SOC-ALT-2026-004** | `100005` | Defense Evasion | `T1059.001` | Medium (8) | Base64 Encoded PowerShell execution | True Positive (Simulated) |
