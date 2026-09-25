# IOC / SECURITY ALERT DETECTION & INVESTIGATION
## Final Project Presentation Slide Deck (14 Slides)

---

### SLIDE 1: Title Slide
- **Slide Title:** IOC / Security Alert Detection & Investigation
- **Subtitle:** Building an Isolated Defensive SOC Lab using Wazuh SIEM & Microsoft Sysmon
- **Presenter:** [Your Name] | Roll No: [Your Roll Number]
- **Department:** Department of Computer Science & Engineering / Information Security
- **Faculty Guide:** [Guide Name, Designation]
- **Academic Year:** 2025–2026
- **Visual:** Project logo / Wazuh Shield logo and college crest.
> **Speaker Notes:**  
> "Good morning respected professors and panel members. Today I am presenting my final project titled 'IOC / Security Alert Detection & Investigation'. In this project, I have designed and deployed an end-to-end Security Operations Center (SOC) lab using open-source Wazuh SIEM, enriched endpoint sensors, and custom detection engineering to detect, investigate, and contain cyber threats in real time."

---

### SLIDE 2: Problem Statement & Motivation
- **Slide Title:** Problem Statement & Industry Motivation
- **Bullet Points:**
  - **Traditional Logging Blind Spots:** Standard Windows Event Logs (Event ID 4688) omit process hashes (SHA256) and truncate command-line scripts.
  - **Alert Fatigue:** SOC teams face millions of un-correlated logs without actionable threat context.
  - **Evolving Threat Vectors:** Modern attacks utilize Living-off-the-Land Binaries (LOLBins) and obfuscated scripts that evade basic antivirus.
  - **Lack of Practical SOC Training:** Need for an isolated, safe, reproducible lab environment to study detection engineering and incident triage.
- **Visual:** Diagram contrasting "Noisy Raw Logs" vs "Enriched Actionable Alerts".
> **Speaker Notes:**  
> "The core motivation behind this project is solving the endpoint telemetry blind spot. By default, Windows does not calculate cryptographic hashes for running processes, making hash-based IOC detection impossible. Furthermore, without correlation, analysts drown in alert fatigue."

---

### SLIDE 3: Project Objectives
- **Slide Title:** Project Objectives
- **Bullet Points:**
  - **Deploy an Isolated SOC Lab:** Host Wazuh SIEM All-in-One server on Ubuntu Linux and connect a monitored Windows endpoint.
  - **Enrich Endpoint Telemetry:** Deploy Microsoft Sysmon to capture granular process trees, network sockets, and SHA256 hashes.
  - **Real-Time Directory Tamper Detection:** Configure Wazuh File Integrity Monitoring (FIM) over critical assets.
  - **Engineer Custom Detection Rules:** Build MITRE ATT&CK mapped rules for C2 beaconing, payload droppers, ransomware notes, and obfuscated PowerShell.
  - **Execute Safe Threat Simulations:** Validate detection logic using harmless, reproducible test indicators.
  - **Perform Forensic Triage & Response:** Conduct structured SOC analyst investigation and enforce host-level containment.
- **Visual:** High-level project lifecycle icon workflow.
> **Speaker Notes:**  
> "Our primary objective was to build a complete defensive loop: from log ingestion to detection engineering, forensic triage, and automated containment, completely aligned with industry standards like NIST and MITRE ATT&CK."

---

### SLIDE 4: System Architecture & Data Flow
- **Slide Title:** System Architecture & Data Flow
- **Bullet Points:**
  - **Isolated Virtual Network:** Ubuntu Server VM (Wazuh SIEM) and Windows Endpoint VM running concurrently.
  - **Encrypted Ingestion Channel:** Wazuh Agent streams event data to Manager over Port 1514 (TLS).
  - **Decoupled Architecture:**
    - **Wazuh Manager:** Parsing, decoding, and rule evaluation.
    - **Wazuh Indexer:** High-speed OpenSearch distributed database.
    - **Wazuh Dashboard:** Analyst web UI for visualization and search.
- **Visual:** Lab Architecture Diagram from Figure 1.1 / Phase 1 blueprint.
> **Speaker Notes:**  
> "This architecture diagram shows the data flow. The Windows endpoint runs Sysmon and the Wazuh Agent. All telemetry is encrypted and shipped to the Ubuntu Wazuh Server over port 1514. The Manager matches events against our custom rules, and indexed alerts appear on the web dashboard within 3 seconds."

---

### SLIDE 5: Technology Stack
- **Slide Title:** Technology Stack & Tools
- **Bullet Points:**
  - **SIEM Engine:** Wazuh SIEM 4.9 (Manager, Indexer, Dashboard)
  - **Endpoint Sensor:** Microsoft Sysmon v15 (Sysinternals)
  - **Server OS:** Ubuntu Server 22.04 LTS
  - **Client Endpoint OS:** Windows 10/11 Enterprise
  - **Hypervisor:** Oracle VirtualBox / VMware Workstation
  - **Automation & Scripting:** PowerShell & Linux Bash
  - **Threat Frameworks:** MITRE ATT&CK, David Bianco's Pyramid of Pain, RFC 5737
- **Visual:** Logos of Wazuh, Ubuntu, Microsoft Sysinternals, and MITRE.
> **Speaker Notes:**  
> "We utilized an enterprise-grade open-source stack. Wazuh provides the SIEM and OpenSearch backend, Microsoft Sysmon gives us kernel-level visibility, and PowerShell drives our automated configuration, simulation, and defensive response."

---

### SLIDE 6: Wazuh SIEM Central Setup
- **Slide Title:** Wazuh SIEM Server Deployment
- **Bullet Points:**
  - **Automated All-in-One Deployment:** Used official Wazuh assistant script with automated SSL certificate generation.
  - **Resource Optimization:** Configured 4GB RAM allocation with a dedicated 2GB swap space for indexer stability.
  - **Network Hardening (UFW Firewall):**
    - Port `443/tcp`: Secure Web Dashboard
    - Port `1514/tcp`: Agent Event Streaming
    - Port `1515/tcp`: Agent Registration
  - **Service Health Verification:** All core services (`wazuh-manager`, `wazuh-indexer`, `wazuh-dashboard`) running in verified healthy states.
- **Visual:** Screenshot of `systemctl status` showing all three green active services (Figure 2.1).
> **Speaker Notes:**  
> "On the server side, we deployed the Wazuh All-in-One stack on Ubuntu 22.04 LTS. We tuned system resources and locked down the firewall so only required ports—443 for the dashboard and 1514 for log shipping—are accessible."

---

### SLIDE 7: Enhanced Endpoint Monitoring: Sysmon & FIM
- **Slide Title:** Telemetry Enrichment: Sysmon & Real-Time FIM
- **Bullet Points:**
  - **Why Sysmon?**
    - **Event ID 1:** Process creation with full CommandLine and SHA256 hashes.
    - **Event ID 3:** Network connections initiated by scripts or binaries.
    - **Event ID 11:** File creation tracking.
  - **File Integrity Monitoring (FIM):**
    - Monitored directory: `C:\SOC_Lab_Test\`
    - Attributes: `realtime="yes"` (instant change detection), `report_changes="yes"`, `check_all="yes"`.
- **Visual:** Screenshot of Windows Event Viewer displaying Sysmon Event ID 1 (Figure 3.2).
> **Speaker Notes:**  
> "Here you can see the difference Sysmon makes. Standard Windows logs don't include cryptographic hashes. Sysmon Event ID 1 generates SHA256 signatures in real time, and our FIM engine detects directory changes instantaneously without waiting for scheduled batch scans."

---

### SLIDE 8: Detection Engineering & Threat Intelligence (IOCs)
- **Slide Title:** Detection Engineering & IOC Formulation
- **Bullet Points:**
  - **Pyramid of Pain Integration:**
    - **Hash IOCs:** Known malicious test SHA256 signatures.
    - **IP IOCs:** C2 test IPs using RFC 5737 documentation ranges (`203.0.113.50`).
    - **Host Artifacts:** Masquerading filenames (`invoice_malware_sim.exe`).
    - **TTPs:** Obfuscated Base64 PowerShell commands and brute-force patterns.
  - **Safety Guarantee:** 100% safe, non-destructive educational indicators.
- **Visual:** Graphic of David Bianco's Pyramid of Pain with our lab IOCs mapped to each layer.
> **Speaker Notes:**  
> "In detection engineering, we applied David Bianco's Pyramid of Pain. We didn't just stop at simple hash and IP matching; we built rules that detect TTPs—such as Base64 encoded PowerShell executions and brute-force authentication behavior."

---

### SLIDE 9: Custom Detection Rules (local_rules.xml)
- **Slide Title:** Custom Wazuh Detection Rules
- **Bullet Points:**
  - **Rule 100001 (Level 12 - Critical):** Outbound connection to Known Malicious C2 Test IP (`MITRE T1071.001`).
  - **Rule 100002 (Level 13 - Critical):** Execution of process matching Known Malicious Test Hash (`MITRE T1204.002`).
  - **Rule 100003 (Level 10 - High):** Suspicious test dropper created on disk (`MITRE T1105`).
  - **Rule 100004 (Level 11 - High):** Potential Ransomware Indicator - Ransom note dropped (`MITRE T1486`).
  - **Rule 100005 (Level 8 - Medium):** Obfuscated Base64 Encoded PowerShell command detected (`MITRE T1059.001`).
  - **Rule 100006 (Level 10 - High):** 3+ failed Windows logins within 60s from same host (`MITRE T1110`).
- **Visual:** Screenshot of `local_rules.xml` in Wazuh Management GUI (Figure 4.2).
> **Speaker Notes:**  
> "These are the 6 custom rules we engineered and deployed into local_rules.xml. Every rule is assigned an alert level from 8 to 13 and directly tagged with its official MITRE ATT&CK technique ID for cross-industry threat mapping."

---

### SLIDE 10: Alert Generation & Controlled Threat Simulation
- **Slide Title:** Alert Generation & Controlled Simulation
- **Bullet Points:**
  - **Automated Safe Simulator:** Custom PowerShell script `simulate_ioc_event.ps1`.
  - **Simulation Scenarios:**
    - Non-destructive TCP SYN handshake to C2 test IP `203.0.113.50:443`.
    - Dropping simulated executable `invoice_malware_sim.exe`.
    - Dropping educational ransom notice `test_ransom_note.txt`.
    - Executing harmless encoded PowerShell string.
  - **Real-Time Alerts:** All 4 events triggered designated rules on the Wazuh Dashboard within 3 seconds.
- **Visual:** Side-by-side view: PowerShell script running on Windows vs Red Critical Alerts popping up on Wazuh Dashboard (Figures 5.1 & 5.2).
> **Speaker Notes:**  
> "To test our detection rules, we authored a safe PowerShell simulator. It executed the 4 test scenarios without using any malicious payloads. As seen on screen, the SIEM generated high and critical severity alerts in real time."

---

### SLIDE 11: Security Alert Investigation & Forensic Triage
- **Slide Title:** Alert Investigation & Forensic Triage
- **Bullet Points:**
  - **Structured SOC Triage Workflow:**
    1. **Triage:** Inspect Alert ID, Rule ID, Severity Level, and Source Asset.
    2. **Attribution:** Extract initiating process (`powershell.exe`), Process ID (`4892`), and User (`socadmin`).
    3. **Correlation:** Trace parent process tree in Sysmon Event ID 1.
    4. **Forensic Verification:** Examine raw JSON parameters (Destination IP, TargetFilename, Hashes).
  - **Finding:** Verified all alerts as **True Positives (Controlled Lab Simulations)**.
- **Visual:** Screenshot of expanded JSON alert record showing forensic fields (Figure 5.3).
> **Speaker Notes:**  
> "As a Tier-1 SOC analyst, detecting the alert is only half the battle. We drilled down into the raw JSON event logs, correlated the parent-child process tree, verified the initiating script, and confirmed each incident as a validated True Positive."

---

### SLIDE 12: Defensive Containment & Incident Response
- **Slide Title:** Defensive Containment & Incident Response
- **Bullet Points:**
  - **NIST SP 800-61 / SANS Alignment:**
    - *Detection -> Validation -> Containment -> Recovery -> Documentation*
  - **Automated Host Containment (`containment_simulation.ps1`):**
    - **Network Isolation:** Injected Windows Defender Firewall outbound block rule for C2 IP `203.0.113.50`.
    - **Artifact Quarantine:** Moved `invoice_malware_sim.exe` into safe vault `C:\SOC_Lab_Quarantine\`.
    - **Recovery:** Cleaned temporary simulation artifacts and verified baseline integrity.
- **Visual:** Windows Defender Firewall GUI showing active Outbound Block Rule (Figure 6.2).
> **Speaker Notes:**  
> "Following NIST guidelines, we executed active containment. We applied host firewall block rules to sever C2 communications, quarantined suspicious binaries into an isolated vault, and verified system integrity without damaging host stability."

---

### SLIDE 13: Results & Empirical Findings
- **Slide Title:** Project Results & Empirical Metrics
- **Bullet Points:**
  - **Mean Detection Latency:** Under **3.0 seconds** from event generation to dashboard indexing.
  - **Detection Accuracy:** **100% detection rate** across all 3 test cases (C2 beaconing, FIM note, brute-force).
  - **Zero False Positives:** Well-tuned regex and specific event channel filters eliminated false alarms.
  - **Master Dashboard:** Consolidated single-pane-of-glass interface displaying metrics, severity breakdown, top rules, and active IOC feeds.
- **Visual:** Master SOC Dashboard Overview Screenshot (Figure 7.1).
> **Speaker Notes:**  
> "Our results demonstrate the efficiency of this architecture. Detection latency averaged under 3 seconds with a 100% detection rate during testing. The master dashboard provides SOC analysts with complete operational visibility from a single pane of glass."

---

### SLIDE 14: Conclusion, Future Scope & Q&A
- **Slide Title:** Conclusion & Future Scope
- **Bullet Points:**
  - **Conclusion:**
    - Successfully built an enterprise-grade, virtualized SOC detection lab.
    - Demonstrated full defensive lifecycle: ingestion, detection engineering, triage, and response.
  - **Future Enhancements:**
    - Implement Wazuh Active Response for automated real-time process termination.
    - Integrate open-source SOAR (Shuffle) for automated threat intelligence lookups.
    - Subscribe to live MISP threat intelligence feeds.
  - **Open for Questions & Answers**
- **Visual:** "Thank You! Questions & Discussion" banner.
> **Speaker Notes:**  
> "In conclusion, this project establishes a practical, robust foundation in modern SOC operations and detection engineering. In the future, this can be expanded with SOAR automation and live threat intelligence. Thank you for your time, and I am now open to your questions."
