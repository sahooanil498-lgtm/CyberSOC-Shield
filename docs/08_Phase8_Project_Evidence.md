# PHASE 8: College Project Evidence & Screenshot Guide

---

## 1. Overview of Phase 8
A major criterion for evaluation in college engineering projects and cybersecurity lab defense is **irrefutable visual evidence**. External evaluators and professors verify whether you truly built the lab or merely copied theoretical outputs.

This guide provides the exact inventory of **15 essential screenshots** you must capture, including:
1. **What screen to capture** (Navigation path)
2. **What should be visible** (Key indicators & UI elements)
3. **Why the screenshot is important** (Academic & technical significance)
4. **Suggested caption for the project report** (Standard academic format)

---

## 2. Screenshot Inventory & Detailed Instructions

---

### 📸 Screenshot 1: Virtual Machine Lab Topology
1. **What screen to capture:**  
   The Oracle VirtualBox Manager or VMware Workstation main window showing the host environment.
2. **What should be visible:**  
   Both virtual machines in the left inventory list:
   - `Wazuh-SIEM-Server` (Ubuntu 64-bit) — Status: **Running**
   - `WIN-ENDPOINT-01` (Windows 10/11) — Status: **Running**
   - Resource allocation specs (e.g., 4096 MB RAM, 2 vCPUs).
3. **Why it is important:**  
   Proves that you created an isolated virtual lab environment and properly allocated system hardware resources.
4. **Suggested Caption:**  
   *Figure 1.1: Virtualized SOC lab topology showing concurrent execution of Ubuntu Wazuh Server and Windows Endpoint.*

---

### 📸 Screenshot 2: Wazuh Central Services Operational Status
1. **What screen to capture:**  
   Ubuntu Server terminal window after running `systemctl status`.
2. **What should be visible:**  
   Output of:
   ```bash
   sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard --no-pager
   ```
   Green highlighted text showing: `Active: active (running)` for all three daemons.
3. **Why it is important:**  
   Demonstrates that the SIEM engine (Manager), document database (Indexer), and UI server (Dashboard) are healthy and communicating.
4. **Suggested Caption:**  
   *Figure 2.1: Verification of active system services for Wazuh Manager, Indexer, and Dashboard on Ubuntu Linux.*

---

### 📸 Screenshot 3: Endpoint Sensors Verification (Wazuh Agent & Sysmon)
1. **What screen to capture:**  
   Windows PowerShell (Run as Administrator) or Windows Services (`services.msc`).
2. **What should be visible:**  
   Output of:
   ```powershell
   Get-Service -Name "WazuhSvc", "Sysmon64"
   ```
   Showing both services with Status: **Running**.
3. **Why it is important:**  
   Proves that the endpoint has both the log forwarding agent (`WazuhSvc`) and the kernel-level telemetry driver (`Sysmon64`) active.
4. **Suggested Caption:**  
   *Figure 3.1: Windows endpoint service verification displaying active status for Wazuh Agent and Microsoft Sysmon.*

---

### 📸 Screenshot 4: Sysmon Granular Telemetry (Event Viewer)
1. **What screen to capture:**  
   Windows **Event Viewer** (`eventvwr.msc`).
2. **What should be visible:**  
   Path: `Applications and Services Logs > Microsoft > Windows > Sysmon > Operational`.  
   Select an **Event ID 1 (Process Create)** record showing:
   - Full `CommandLine`
   - `ParentImage` (e.g., `cmd.exe` or `powershell.exe`)
   - `Hashes` (SHA256, MD5)
3. **Why it is important:**  
   Proves that your endpoint is capturing deep telemetry beyond standard Windows Event ID 4688 logs, enabling IOC hash matching.
4. **Suggested Caption:**  
   *Figure 3.2: Microsoft Sysmon Event ID 1 in Windows Event Viewer displaying rich process metadata and SHA256 hashes.*

---

### 📸 Screenshot 5: Wazuh SIEM Dashboard — Active Agent Enrollment
1. **What screen to capture:**  
   Wazuh Web Dashboard (`https://<Ubuntu_IP>`) -> Navigation Menu (☰) -> **Endpoints Summary** (or **Agents**).
2. **What should be visible:**  
   - Total Agents: `1`
   - Active Agents: `1` (Green circular badge)
   - Agent Name: `WIN-ENDPOINT-01`
   - Operating System: `Microsoft Windows`
   - IP address: `192.168.x.x`
3. **Why it is important:**  
   Direct visual proof that the Windows endpoint successfully established an authenticated, encrypted channel to the Wazuh Manager.
4. **Suggested Caption:**  
   *Figure 4.1: Wazuh SIEM Endpoints Summary confirming active enrollment of the Windows monitored system.*

---

### 📸 Screenshot 6: Custom Detection Rules Deployment
1. **What screen to capture:**  
   Wazuh Dashboard -> **Management** -> **Rules** -> `local_rules.xml`.
2. **What should be visible:**  
   The XML editor showing your custom rules:
   - Rule `100001` (C2 IP matching)
   - Rule `100003` (Suspicious file dropper)
   - Rule `100004` (Ransomware note detection)
   - Rule `100005` (Encoded PowerShell)
3. **Why it is important:**  
   Demonstrates custom rule engineering and shows that you wrote defensive logic rather than just using default rules.
4. **Suggested Caption:**  
   *Figure 4.2: Deployment of custom SOC detection rules (Rules 100001–100005) in local_rules.xml on Wazuh Manager.*

---

### 📸 Screenshot 7: Safe Threat Simulation Execution
1. **What screen to capture:**  
   Windows PowerShell window executing `simulate_ioc_event.ps1`.
2. **What should be visible:**  
   The colorful console banner and output:
   - `[TEST 1] Simulating C2 Connection to RFC Test IP 203.0.113.50... [DONE]`
   - `[TEST 2] Simulating Suspicious Payload Drop: invoice_malware_sim.exe... [DONE]`
   - `[TEST 3] Simulating Ransomware Indicator: test_ransom_note.txt... [DONE]`
   - `[TEST 4] Simulating Encoded PowerShell Command... [DONE]`
3. **Why it is important:**  
   Documents the controlled and benign methodology used to generate reproducible security events.
4. **Suggested Caption:**  
   *Figure 5.1: Execution of safe PowerShell threat simulation script triggering test IOC events.*

---

### 📸 Screenshot 8: Security Alerts Stream — C2 Connection Alert (Rule 100001)
1. **What screen to capture:**  
   Wazuh Dashboard -> **Security events**.
2. **What should be visible:**  
   An alert row highlighted with **Level 12 (Critical)**:
   - Description: `SOC-LAB ALERT [CRITICAL]: Outbound network connection to Known Malicious C2 Test IP (203.0.113.50)...`
   - Agent Name: `WIN-ENDPOINT-01`
   - Rule ID: `100001`
3. **Why it is important:**  
   Core evidence of proactive IOC detection based on real-time network telemetry.
4. **Suggested Caption:**  
   *Figure 5.2: Wazuh SIEM real-time critical security alert for outbound connection to known C2 test indicator.*

---

### 📸 Screenshot 9: Raw JSON Forensic Log Evidence
1. **What screen to capture:**  
   Clicking the dropdown arrow on the Rule 100001 alert in Wazuh Dashboard to expand the full event record.
2. **What should be visible:**  
   The structured JSON document showing:
   - `data.win.system.eventID`: `3`
   - `data.win.eventdata.destinationIp`: `203.0.113.50`
   - `data.win.eventdata.destinationPort`: `443`
   - `data.win.eventdata.image`: `powershell.exe`
   - `rule.mitre.id`: `T1071.001`
3. **Why it is important:**  
   Shows that you know how to read and interpret raw log fields during a forensic investigation.
4. **Suggested Caption:**  
   *Figure 5.3: Expanded JSON telemetry payload revealing forensic parameters and MITRE ATT&CK mapping.*

---

### 📸 Screenshot 10: Suspicious Dropper File Alert (Rule 100003)
1. **What screen to capture:**  
   Wazuh Dashboard -> Security events filtered by `rule.id: 100003`.
2. **What should be visible:**  
   Alert description: `SOC-LAB ALERT [MEDIUM]: Suspicious test dropper or payload created on disk: invoice_malware_sim.exe`.
3. **Why it is important:**  
   Proves endpoint file creation monitoring and detection of masquerading filenames.
4. **Suggested Caption:**  
   *Figure 5.4: Wazuh alert detecting unauthorized payload creation matching suspicious naming convention.*

---

### 📸 Screenshot 11: Real-Time File Integrity Monitoring (FIM) Alert (Rule 100004 & 550)
1. **What screen to capture:**  
   Wazuh Dashboard -> Navigation Menu (☰) -> **Integrity monitoring** -> **Events**.
2. **What should be visible:**  
   - File Path: `C:\SOC_Lab_Test\test_ransom_note.txt`
   - Event: `added`
   - Calculated SHA256 hash
   - Associated Rule ID: `100004` / `550`
3. **Why it is important:**  
   Demonstrates Wazuh's FIM capability to detect extortion indicators and unauthorized directory alterations within seconds.
4. **Suggested Caption:**  
   *Figure 5.5: File Integrity Monitoring (FIM) event capturing creation of simulated ransomware extortion note.*

---

### 📸 Screenshot 12: Obfuscated Base64 PowerShell Execution Alert (Rule 100005)
1. **What screen to capture:**  
   Wazuh Dashboard -> Security events filtered by `rule.id: 100005`.
2. **What should be visible:**  
   - Rule Description: `SOC-LAB ALERT [MEDIUM]: Obfuscated or Base64 Encoded PowerShell command line detected`.
   - Command-line field displaying the `-EncodedCommand` parameter.
3. **Why it is important:**  
   Proves detection of living-off-the-land techniques and defense evasion strategies.
4. **Suggested Caption:**  
   *Figure 5.6: Detection of defense evasion technique using Base64 encoded PowerShell command execution.*

---

### 📸 Screenshot 13: Defensive Incident Response Execution
1. **What screen to capture:**  
   Windows PowerShell executing `containment_simulation.ps1`.
2. **What should be visible:**  
   - `[CONTAINMENT] Applying Windows Defender Firewall Block Rule... [DONE]`
   - `[CONTAINMENT] Artifact neutralized and moved to C:\SOC_Lab_Quarantine... [DONE]`
   - Clean folder status confirmation.
3. **Why it is important:**  
   Demonstrates active containment and remediation rather than just passive detection.
4. **Suggested Caption:**  
   *Figure 6.1: Automated defensive incident response executing host firewall containment and artifact quarantine.*

---

### 📸 Screenshot 14: Windows Defender Firewall Active Containment Rule
1. **What screen to capture:**  
   Windows **Windows Defender Firewall with Advanced Security** (`wf.msc`) -> **Outbound Rules**.
2. **What should be visible:**  
   Rule named **`SOC_LAB_BLOCK_MALICIOUS_C2_TEST_IP`**:
   - Action: **Block the connection** (Red circle with slash icon)
   - Remote IP: `203.0.113.50`
   - Protocol: TCP
3. **Why it is important:**  
   Hard system proof that network isolation and host containment were enforced.
4. **Suggested Caption:**  
   *Figure 6.2: Windows Defender Firewall interface displaying active outbound block rule isolating the C2 test IP.*

---

### 📸 Screenshot 15: Master SOC Analytics Dashboard Overview
1. **What screen to capture:**  
   Wazuh Dashboard -> OpenSearch Dashboards -> View of **`SOC Lab - Threat Detection & IOC Monitoring Dashboard`**.
2. **What should be visible:**  
   The full comprehensive layout showing:
   - Metric card: `Critical Alerts: 4`
   - Pie chart: Alert severity distribution
   - Horizontal bar chart: Top triggered detection rules
   - Table: Live IOC events
3. **Why it is important:**  
   The centerpiece visual for your final presentation slide deck and project report front pages.
4. **Suggested Caption:**  
   *Figure 7.1: Master SOC Threat Detection and IOC Monitoring Dashboard consolidating alerts, metrics, and incident telemetry.*
