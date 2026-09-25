# SOC INCIDENT INVESTIGATION REPORT (DOSSIER)
### Academic Project Submission — Department of Computer Science / Cybersecurity

**Project Title:** IOC / Security Alert Detection & Investigation using Wazuh SIEM  
**Investigating Analyst:** [Your Name / Roll No]  
**Lead Evaluator / Faculty Guide:** [Faculty Name]  
**Lab Environment:** Virtual SOC Lab (Ubuntu Wazuh Server + Windows 10 Monitored Endpoint)  
**Date of Incident Analysis:** 2026-09-25  

---

## 1. Executive Summary
During continuous security monitoring of the endpoint **`WIN-ENDPOINT-01`** (IP: `192.168.1.151`), the Wazuh SIEM platform generated multiple high-severity security alerts within a compressed timeframe. Threat correlation identified an intrusion simulation involving:
1. Obfuscated PowerShell execution attempt.
2. Ingress transfer of a suspicious executable dropper (`invoice_malware_sim.exe`).
3. Outbound network beaconing towards a known malicious C2 test IP (`203.0.113.50`).
4. Extortion notice artifact generation (`test_ransom_note.txt`).

All alerts were successfully triaged, correlated with Sysmon Event logs and Wazuh FIM records, and validated as **True Positives (Controlled Lab Simulations)**.

---

## 2. Incident Timeline

| UTC Timestamp | Event Source | Rule ID | Event Description | Action Taken |
| :--- | :--- | :--- | :--- | :--- |
| `10:35:12` | Sysmon Event 3 | `100001` | Outbound TCP SYN to C2 test IP `203.0.113.50:443` | Destination IP validated against IOC database; Alert escalated to Tier-2. |
| `10:35:13` | Sysmon Event 11 | `100003` | File created: `invoice_malware_sim.exe` | Artifact quarantined; SHA256 signature calculated. |
| `10:35:14` | Wazuh FIM | `100004` | File created: `test_ransom_note.txt` in `C:\SOC_Lab_Test` | Verified volume shadow copies; Checked for bulk file encryption. |
| `10:35:15` | Sysmon Event 1 | `100005` | Encoded PowerShell command execution | Extracted Base64 payload and de-obfuscated script text. |

---

## 3. Detailed Forensic Evidence Analysis

### Artifact A: Command and Control (C2) Communication
- **Initiating Binary:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- **Source IP / Port:** `192.168.1.151:52814`
- **Destination IP / Port:** `203.0.113.50:443`
- **Analysis:** Direct outbound socket call to untrusted documentation network. Confirms that endpoint security sensors successfully intercepted command-and-control handshakes.

### Artifact B: De-Obfuscated Command-Line Script
- **Raw Argument:** `-EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACcAUwBPAEMALQBMAGEAYgAtAEIAZQBuAGkAZwBuAC0AUwBpAG0AdQBsAGEAdABpAG8AbgAtAFQAZQBzAHQAaQBuAGcAJwA=`
- **Decoded Content:** `Write-Host 'SOC-Lab-Benign-Simulation-Testing'`
- **Analysis:** Demonstration of defense evasion via command obfuscation. SIEM alerted on the evasion technique itself (Rule 100005).

### Artifact C: File Integrity Monitoring Baseline
- **Path:** `C:\SOC_Lab_Test\test_ransom_note.txt`
- **Calculated SHA256:** `4a1b025fbc77660c6753a798a69eef52467d302a281898114f6d4d161d713c23`
- **Analysis:** Real-time FIM verified that system changes inside sensitive folders are detected instantaneously without waiting for scheduled batch scans.

---

## 4. Remediation & Defensive Recommendations
1. **Network Layer:** Block RFC test range `203.0.113.0/24` and suspicious outbound ports at boundary perimeter firewall.
2. **Endpoint Layer:** Enable PowerShell Constrained Language Mode (CLM) and AppLocker / Software Restriction Policies to prevent unapproved executables running from user-writable directories.
3. **Detection Engineering:** Maintain and update Wazuh CDB lists with updated threat intelligence feeds (AlienVault OTX, MISP).
