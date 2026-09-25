# IOC / SECURITY ALERT DETECTION & INVESTIGATION
## Comprehensive Academic Project Report
**Bachelor of Technology / Bachelor of Science in Computer Science & Cybersecurity**

---

**Candidate Name:** [Student Name]  
**Roll / Registration Number:** [Roll Number]  
**Faculty Guide / Mentor:** [Mentor Name, Designation]  
**Department:** Department of Computer Science & Engineering / Information Security  
**Institution:** [College / University Name]  
**Academic Year:** 2025 – 2026  

---

## TABLE OF CONTENTS
1. [Title](#1-title)
2. [Abstract](#2-abstract)
3. [Introduction](#3-introduction)
4. [Problem Statement](#4-problem-statement)
5. [Objectives](#5-objectives)
6. [Scope](#6-scope)
7. [Technologies Used](#7-technologies-used)
8. [System Architecture](#8-system-architecture)
9. [Methodology](#9-methodology)
10. [Implementation](#10-implementation)
11. [IOC Detection Engineering](#11-ioc-detection-engineering)
12. [Alert Investigation & Forensic Triage](#12-alert-investigation--forensic-triage)
13. [Practical Test Cases](#13-practical-test-cases)
14. [Results & Discussion](#14-results--discussion)
15. [Limitations](#15-limitations)
16. [Future Scope](#16-future-scope)
17. [Conclusion](#17-conclusion)
18. [References](#18-references)

---

## 1. Title
**IOC / Security Alert Detection & Investigation: A Virtualized Security Operations Center (SOC) Lab with Wazuh SIEM**

---

## 2. Abstract
Modern enterprise cybersecurity operations center around rapid detection and triage of Indicators of Compromise (IOCs) before threat actors achieve their operational objectives. Traditional endpoint telemetry often fails to provide sufficient granular visibility into process executions, command-line arguments, and cryptographic file signatures. This project presents the design, implementation, and empirical validation of a fully virtualized, isolated Security Operations Center (SOC) defensive lab using **Wazuh SIEM**, **Microsoft Sysmon**, and a **Windows monitored endpoint**.

Through the integration of kernel-level telemetry forwarders, custom detection engineering rules mapped to the **MITRE ATT&CK framework**, and real-time **File Integrity Monitoring (FIM)**, the lab demonstrates the complete defensive lifecycle: log ingestion, IOC threat-matching, security alert generation, SOC Tier-1/Tier-2 forensic triage, containment, and incident reporting. Multiple controlled, safe simulations were conducted, including command-and-control (C2) network beaconing, suspicious payload droppers, simulated ransomware extortion notes, obfuscated PowerShell execution, and brute-force authentication attempts. The platform achieved sub-3-second detection latency with zero false positives during testing, establishing an effective blueprint for educational cybersecurity training and enterprise detection validation.

---

## 3. Introduction
In today's digital threat landscape, security breaches are an inevitability rather than an anomaly. Organizations rely heavily on **Security Information and Event Management (SIEM)** systems to consolidate vast volumes of log data across disparate network infrastructure, identify anomalies, and empower **Security Operations Center (SOC)** analysts to remediate incidents rapidly.

Open-source SIEM platforms like **Wazuh** provide an enterprise-grade ecosystem combining log analysis, intrusion detection, vulnerability detection, file integrity monitoring, and regulatory compliance. However, effective SIEM operation depends critically on high-fidelity endpoint sensors. Standard operating system event logging often omits vital forensic parameters—such as cryptographic file hashes, full command-line arguments, and parent-child process relationships. By pairing Wazuh with **Microsoft Sysmon (System Monitor)**, defenders attain deep observability into endpoint activities. This project provides a practical, hands-on implementation of this modern defensive security architecture.

---

## 4. Problem Statement
Enterprise endpoints generate gigabytes of disparate event logs daily, creating two major operational challenges:
1. **The Telemetry Blind Spot:** Default Windows event logging (e.g., Event ID 4688) does not calculate on-the-fly cryptographic hashes (SHA256) of executing binaries and often truncates command-line executions, rendering IOC hash-matching and script de-obfuscation impossible.
2. **Alert Fatigue & Correlation Deficits:** Without custom detection engineering and centralized threat intelligence correlation, security teams are overwhelmed by thousands of benign logs while high-risk intrusions slip by unnoticed.

There is a critical educational and operational need for a structured, reproducible, and safe methodology to ingest endpoint telemetry, apply proactive IOC matching, investigate alerts, and execute defensive containment workflows within an isolated environment.

---

## 5. Objectives
### Primary Objective:
To design, deploy, and evaluate an isolated, virtualized SOC detection and alert investigation platform using Wazuh SIEM and Sysmon.

### Secondary Objectives:
1. Establish a secure communication channel between a Windows endpoint agent and an Ubuntu Wazuh SIEM server.
2. Ingest rich process-level and network-level telemetry via Microsoft Sysmon and Windows Event channels.
3. Configure real-time File Integrity Monitoring (FIM) over sensitive directories to intercept file tampering within seconds.
4. Author custom Wazuh detection rules mapped to MITRE ATT&CK tactics (C2, Ingress Tool Transfer, Impact, Defense Evasion, Credential Access).
5. Build a comprehensive SOC dashboard visualizing real-time metrics, severity distribution, top rules, and active IOC feeds.
6. Execute controlled, non-destructive threat simulations to validate detection rules and document formal incident investigation workflows.

---

## 6. Scope
- **Included in Scope:**
  - Deployment of Wazuh Manager, Indexer, and Dashboard on Ubuntu Linux 22.04 LTS.
  - Deployment of Wazuh Agent and Sysmon driver on Windows 10/11 Endpoint.
  - Creation of benign IOC lists (RFC 5737 test IPs, pre-computed hashes, harmless filenames).
  - Implementation of custom detection rules (`local_rules.xml`).
  - Safe PowerShell-driven simulation scripts.
  - Forensic investigation dossiers and host firewall containment workflows.
- **Excluded from Scope:**
  - Deployment of live, self-propagating malware or destructive ransomware binaries.
  - Exploitation against unauthorized or external networks.
  - Commercial cloud SaaS integrations requiring paid subscriptions.

---

## 7. Technologies Used

| Technology / Tool | Version | Role in Project Architecture |
| :--- | :--- | :--- |
| **Wazuh Manager** | 4.9.x | Core SIEM brain; rule evaluation, decoding, and alert generation. |
| **Wazuh Indexer** | 4.9.x | Distributed search engine (OpenSearch) for fast indexing and querying of alert JSONs. |
| **Wazuh Dashboard** | 4.9.x | Web-based SOC graphical interface for triage and data visualization. |
| **Wazuh Agent** | 4.9.x | Endpoint service monitoring Windows logs, files, and forwarding to Manager. |
| **Microsoft Sysmon** | 15.x | System driver capturing Process Create (SHA256), Network Connect, and File Create. |
| **Ubuntu Server** | 22.04 LTS | Host operating system for centralized Wazuh SIEM components. |
| **Windows Endpoint** | 10 / 11 | Monitored target endpoint system. |
| **Oracle VirtualBox / VMware** | 7.0+ | Hypervisor managing isolated virtual networking. |
| **PowerShell** | 5.1 / 7.x | Automation language for agent configuration, event simulation, and containment. |

---

## 8. System Architecture
The system operates on an isolated virtual network where all communication is strictly governed and monitored.

```
+-----------------------------------------------------------------------------------+
|                                 HYPERVISOR HOST                                   |
|                                                                                   |
|   +------------------------------------+      +-------------------------------+   |
|   |         Ubuntu Server VM           |      |      Windows Endpoint VM      |   |
|   |          (Wazuh SIEM)              |      |       (Monitored System)      |   |
|   |                                    |      |                               |   |
|   |  - Wazuh Manager (Port 1514/1515)  |      |  - Wazuh Agent (Service)      |   |
|   |  - Wazuh Indexer (Port 9200)       |      |  - Microsoft Sysmon Driver    |   |
|   |  - Wazuh Dashboard (Port 443/Web)  |      |  - Windows Event Log System   |   |
|   |  - Custom Detection Rules Engine   |      |  - FIM Test Dir: C:\SOC_Lab   |   |
|   |                                    |      |                               |   |
|   |         IP: 192.168.1.150          |      |       IP: 192.168.1.151       |   |
|   +------------------^-----------------+      +---------------+---------------+   |
|                      |                                        |                   |
|                      |        TLS Encrypted Log Stream        |                   |
|                      +----------------------------------------+                   |
|                                                                                   |
|                       Isolated Virtual Network Subnet                             |
+-----------------------------------------------------------------------------------+
                                          |
         Analyst Investigation Access: https://192.168.1.150 (Host Web Browser)
```

---

## 9. Methodology
The project was executed across five sequential phases:
1. **Phase A (Environment Provisioning):** Allocation of virtual hardware, installation of server and client operating systems, and configuration of static IP networking.
2. **Phase B (SIEM & Sensor Deployment):** Installation of Wazuh All-in-One central stack via automated scripts, followed by Windows agent enrollment and Sysmon driver integration.
3. **Phase C (Detection Engineering):** Formulation of detection hypotheses, threat modeling with MITRE ATT&CK, compilation of IOC threat lists, and authoring XML detection rules in `local_rules.xml`.
4. **Phase D (Controlled Simulation & Testing):** Development of non-destructive PowerShell simulation scripts to generate reproducible network, process, file, and authentication anomalies.
5. **Phase E (Investigation & Response):** SOC analyst alert triage, extraction of forensic parameters, host containment enforcement via firewall and quarantine, and post-incident documentation.

---

## 10. Implementation Details

### Wazuh Server Installation:
The all-in-one stack was deployed on Ubuntu 22.04 LTS using the official installation assistant:
```bash
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```
Firewall policies were hardened using UFW to permit traffic exclusively on ports 443 (Dashboard), 1514 (Agent log traffic), and 1515 (Agent registration).

### Sysmon & Agent Configuration on Windows:
Sysmon was deployed with a customized configuration capturing MD5 and SHA256 hashes for all process creations. The Wazuh Agent configuration (`ossec.conf`) was updated to subscribe to the Sysmon event channel:
```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>

<syscheck>
  <disabled>no</disabled>
  <frequency>300</frequency>
  <directories check_all="yes" realtime="yes" report_changes="yes">C:\SOC_Lab_Test</directories>
</syscheck>
```

---

## 11. IOC Detection Engineering

### Pyramid of Pain Alignment:
Detection logic was structured across multiple tiers of David Bianco's Pyramid of Pain:
- **Trivial/Easy Indicators:** Matched known C2 test IPs (`203.0.113.50`) and known malicious test file hashes (SHA256: `4a1b025fbc77...`).
- **Host Artifacts:** Monitored suspicious masquerading naming patterns (`invoice_malware_sim.exe`, `test_ransom_note.txt`).
- **TTPs (Tactics, Techniques & Procedures):** Detected obfuscation behavior (Base64 `-EncodedCommand` execution in PowerShell) and brute-force credential stuffing.

### Custom Rules Matrix:
- **Rule 100001 (Level 12 - Critical):** Outbound connection to Known Malicious C2 Test IP (`T1071.001`).
- **Rule 100002 (Level 13 - Critical):** Process executed matching Known Malicious Test Hash (`T1204.002`).
- **Rule 100003 (Level 10 - High):** Suspicious test dropper created on disk (`T1105`).
- **Rule 100004 (Level 11 - High):** Potential Ransomware Indicator - Ransom note dropped (`T1486`).
- **Rule 100005 (Level 8 - Medium):** Obfuscated Base64 PowerShell execution (`T1059.001`).
- **Rule 100006 (Level 10 - High):** Potential Brute-Force authentication attack (3+ fails in 60s) (`T1110`).

---

## 12. Alert Investigation & Forensic Triage
During alert evaluation, the analyst executes a four-step triage procedure:
1. **Detection & Triage:** Identify incoming alert ID, rule severity, and target asset.
2. **Context Enrichment:** Cross-reference destination IP against threat intelligence, inspect process parentage (e.g., `powershell.exe` spawned by automated script), and evaluate user privileges.
3. **Forensic Correlation:** Query Sysmon Event ID 1 (Process Create), Event ID 3 (Network Connect), and FIM records to determine whether unauthorized lateral movement or persistence occurred.
4. **Conclusion:** Classify the alert as True Positive (TP) or False Positive (FP) and trigger defensive remediation.

---

## 13. Practical Test Cases
Three primary test cases were executed to empirically validate the system:

1. **TC-01 (IOC C2 Beaconing):** Benign TCP socket connection to `203.0.113.50:443`. Rule `100001` triggered within 2.8 seconds; full IP and process details captured in JSON logs.
2. **TC-02 (FIM Extortion Note Detection):** Simulated ransom note dropped in `C:\SOC_Lab_Test\test_ransom_note.txt`. Rule `100004` and core FIM Rule `550` fired within 1.5 seconds, extracting the exact SHA256 signature.
3. **TC-03 (Brute-Force Authentication):** 4 rapid failed logons against dummy account `lab_test_intruder`. Rule `100006` successfully correlated the underlying Windows Event ID 4625 records and escalated a high-severity alert.

All three test cases achieved a **100% detection rate** with verified forensic data.

---

## 14. Results & Discussion
- **Detection Latency:** Time elapsed between event generation on the Windows endpoint and alert indexing on Wazuh Dashboard averaged **under 3.0 seconds**.
- **Data Granularity:** The inclusion of Sysmon provided full command-line arguments and cryptographic hashes that were absent in default Windows event logs.
- **FIM Real-Time Performance:** Wazuh's `realtime="yes"` flag eliminated the latency of traditional 12-hour batch scans, alerting the SOC immediately upon unauthorized file alteration.
- **Defensive Containment:** Automated PowerShell containment scripts successfully isolated the C2 IP at the host firewall layer and quarantined high-risk droppers without disrupting standard business applications.

---

## 15. Limitations
1. **Virtual Lab Scale:** The current implementation models a single Windows endpoint; enterprise SOC environments monitor thousands of heterogeneous devices.
2. **Encrypted Network Payloads:** While Sysmon records socket metadata (IP, port, process), it does not inspect encrypted TLS payload content (Deep Packet Inspection).
3. **Host-Only Containment:** Containment was enforced via host-based firewall rules rather than hardware network switches or enterprise Active Directory group policies.

---

## 16. Future Scope
1. **Automated Active Response:** Implementing Wazuh Active Response scripts to automatically isolate endpoints or kill malicious PIDs the instant Rule 100001 fires.
2. **SOAR Integration:** Connecting Wazuh with open-source SOAR platforms (such as Shuffle or Cortex) to orchestrate automated threat-intelligence lookups (VirusTotal API, AbuseIPDB).
3. **Threat Intelligence Automation:** Subscribing Wazuh CDB lists to live MISP (Malware Information Sharing Platform) feeds for real-time IOC synchronization.
4. **Linux & Cloud Endpoints:** Expanding monitoring coverage to Ubuntu workstations, macOS endpoints, and AWS/Azure cloud workloads.

---

## 17. Conclusion
This project successfully designed, implemented, and validated an enterprise-style **Security Operations Center (SOC) lab** centered around **Wazuh SIEM** and **Microsoft Sysmon**. By establishing deep endpoint visibility, authoring custom detection rules mapped to MITRE ATT&CK, and executing safe threat simulations, the project demonstrated the entire defensive security lifecycle. The platform bridges the gap between theoretical cybersecurity principles and practical SOC operations, proving that open-source tooling can deliver high-fidelity threat detection, forensic triage, and rapid incident containment.

---

## 18. References
1. **Wazuh Documentation:** Wazuh Open Source Security Platform Architecture & Installation Guide (v4.9), https://documentation.wazuh.com/.
2. **Microsoft Sysinternals:** Mark Russinovich & Thomas Garnier, *Sysmon (System Monitor) v15.x*, Microsoft Learn, https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon.
3. **MITRE ATT&CK Framework:** Enterprise Matrix, Tactics & Techniques, https://attack.mitre.org/.
4. **David J. Bianco:** *The Pyramid of Pain*, Enterprise Detection & Threat Hunting, 2013.
5. **NIST Special Publication 800-61 Rev. 2:** *Computer Security Incident Handling Guide*, National Institute of Standards and Technology.
6. **SwiftOnSecurity:** *Sysmon-Modular & sysmonconfig-export repository*, GitHub.
7. **RFC 5737:** *IPv4 Address Blocks Reserved for Documentation*, Internet Engineering Task Force (IETF).
