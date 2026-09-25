# PHASE 12: Comprehensive Viva Voce Oral Defense Guide (Q&A)

---

## 1. Overview & Objective
This guide prepares you for your final academic viva voce, external examiner defense, and technical project evaluation for **IOC / Security Alert Detection & Investigation**.

Examiners typically evaluate your understanding across four core pillars:
1. **Architectural Understanding:** Why specific tools (Wazuh, Sysmon, OpenSearch) were chosen over standard alternatives.
2. **Detection Engineering Logic:** How rules work internally (XML schema, decoders, regex, and stateful correlation).
3. **Forensic & Incident Response Discipline:** How alerts are triaged, verified, contained, and documented.
4. **Hands-On Demonstration Mastery:** Explaining live simulations and demonstrating the CyberSOC Shield web console.

---

## 2. Top 25 Viva Voce Questions & Model Answers

### Domain 1: Architecture & Ingestion Pipeline

#### Q1: What is the core architecture of your SOC project, and how does telemetry travel from the endpoint to the dashboard?
> **Answer:**  
> Our architecture consists of two primary components operating over a secure virtual network:
> 1. **Monitored Endpoint (Windows):** Runs Microsoft Sysmon kernel driver for telemetry enrichment and the Wazuh Agent (`WazuhSvc`).
> 2. **Wazuh All-in-One Server (Ubuntu Linux):** Houses the **Wazuh Manager** (analysis engine running `wazuh-analysisd`), **Wazuh Indexer** (OpenSearch-based distributed search engine), and **Wazuh Dashboard** (analyst web UI).
> 
> **Data Flow:** Sysmon intercepts kernel-level events (Process Create, Network Connect, File Drop) and writes them to the Windows EventChannel (`Microsoft-Windows-Sysmon/Operational`). The Wazuh Agent reads these channels in real time, buffers them, encrypts the payload via AES-256, and forwards it to the Wazuh Manager over **Port 1514 (TCP/UDP)**. The Manager decodes the XML, evaluates it against `local_rules.xml`, and if an alert triggers, flushes it to `alerts.json` and OpenSearch port 9200 for dashboard visualization.

---

#### Q2: Why did you install Microsoft Sysmon when Windows already has native Security Event Logging?
> **Answer:**  
> Native Windows Security logging (e.g., Event ID 4688) has severe operational blind spots for defensive SOC operations:
> - **No Cryptographic Hashes:** Windows Event 4688 does not record SHA256/MD5 hashes of executed binaries; Sysmon Event ID 1 provides SHA256, MD5, and ImpHash out-of-the-box.
> - **Network Association:** Windows Event Log does not tie network socket creation directly to process parentage; Sysmon Event ID 3 provides source IP, destination IP, port, and the exact launching executable.
> - **Process Lineage:** Sysmon generates unique GUIDs (`ProcessGuid` and `ParentProcessGuid`), preventing attackers from disguising attacks through PID reuse.

---

#### Q3: Which network ports are critical for Wazuh operations, and what are their functions?
> **Answer:**  
> - **TCP 1514:** Secure agent-to-manager event ingestion and enrollment protocol.
> - **TCP 1515:** Wazuh Agent registration service (AuthD) for issuing client keys.
> - **TCP 55000:** Wazuh Manager RESTful API for orchestration and configuration management.
> - **TCP 9200:** Wazuh Indexer (OpenSearch) REST API for querying stored alert indices.
> - **TCP 443:** Wazuh Dashboard HTTPS analyst web interface.
> - **TCP 5050:** Our custom CyberSOC Shield endpoint monitoring console.

---

### Domain 2: Detection Engineering & Rule Schema

#### Q4: Walk me through the anatomy of your custom Wazuh detection rules in `local_rules.xml`.
> **Answer:**  
> Custom user rules are assigned Rule IDs starting at **100000** (IDs below 100000 are reserved for built-in rules). Every rule contains:
> - `<rule id="..." level="...">`: Unique identifier and severity rating (1–16).
> - `<if_sid>` or `<if_group>`: Parent rule dependency ensuring modular hierarchy.
> - `<field name="..." type="pcre2">`: Field-matching conditions evaluated against decoded event fields (e.g., `win.eventdata.destinationIp` or `win.eventdata.targetFilename`).
> - `<description>`: Actionable summary describing the detected vector, supporting dynamic replacement variables like `$(win.eventdata.image)`.
> - `<mitre>`: Mapping tags detailing ATT&CK tactics (`<tactic>`) and technique IDs (`<id>`).

---

#### Q5: How does your brute-force authentication rule (Rule 100006) differ from single-event rules?
> **Answer:**  
> Rule 100006 is a **stateful composite frequency rule**, whereas Rules 100001–100005 are atomic single-event rules.  
> It tracks Windows Security Event ID 4625 (Logon Failure) using:
> - `frequency="3"`: Requires at least 3 occurrences to trigger.
> - `timeframe="60"`: Time window of 60 seconds.
> - `<same_field>win.eventdata.targetUserName</same_field>`: Ensures correlation is scoped to the **same attacked username**, preventing false positives across independent user accounts.

---

#### Q6: What is the difference between Wazuh's OS_Regex and PCRE2 regex engines?
> **Answer:**  
> Wazuh's legacy `OS_Regex` engine is a lightweight, POSIX-like regex engine optimized for simple matching but lacking modern regex features. By specifying `type="pcre2"` on rule fields, we enable Perl-Compatible Regular Expressions v2, supporting case-insensitive flags `(?i)`, lookaheads, non-greedy quantifiers, and precise boundary anchors essential for detecting evasive payloads.

---

### Domain 3: Indicators of Compromise (IOCs) & Threat Intelligence

#### Q7: What is David Bianco's "Pyramid of Pain", and where do your detection rules rank on it?
> **Answer:**  
> The Pyramid of Pain categorizes IOC types by how much difficulty tracking them imposes on an adversary:
> 1. **Hash Values (Trivial):** SHA256 match (Rule 100002).
> 2. **IP Addresses (Easy):** C2 socket match to `203.0.113.50` (Rule 100001).
> 3. **Domain Names (Simple):** DNS queries to malicious staging domains.
> 4. **Network / Host Artifacts (Annoying):** Ransomware extortion note dropped on disk (Rule 100004).
> 5. **Tools (Challenging):** Malicious dropper execution (Rule 100003).
> 6. **TTPs - Tactics, Techniques & Procedures (Tough):** Detecting Base64 PowerShell execution (Rule 100005) and Brute-force authentication patterns (Rule 100006).

---

#### Q8: Why did you use `203.0.113.50` as the malicious C2 IP address in your simulations?
> **Answer:**  
> `203.0.113.0/24` is an official **RFC 5737 (TEST-NET-3)** reserved IPv4 documentation block. It is designated by IANA strictly for network documentation and security testing. It is non-routable on the public Internet, ensuring our simulated C2 handshake never generates unauthorized external traffic or impacts live networks.

---

### Domain 4: Threat Simulation & Containment

#### Q9: Explain each of the 5 simulated threat scenarios tested in this project.
> **Answer:**  
> 1. **C2 Network Beaconing (T1071.001):** Executes an outbound TCP socket handshake to `203.0.113.50:443`. Captured by Sysmon Event ID 3 and flagged by Rule 100001.
> 2. **Known Malicious Hash Execution (T1204.002):** Executes a binary whose SHA256 matches our blacklist. Captured by Sysmon Event ID 1 and flagged by Rule 100002.
> 3. **Malicious Dropper Payload (T1105):** Creates simulated executable `invoice_malware_sim.exe` inside `C:\SOC_Lab_Test`. Captured by Sysmon Event ID 11 and flagged by Rule 100003.
> 4. **Ransomware Extortion Note Drop (T1486):** Writes `test_ransom_note.txt` into the monitored directory. Detected instantly by Wazuh Real-Time FIM (syscheck Rule 554) and elevated by Rule 100004.
> 5. **Defense Evasion via Base64 PowerShell (T1059.001):** Spawns `powershell.exe` with `-EncodedCommand` executing a benign string. Intercepted by Sysmon Event ID 1 and flagged by Rule 100005.

---

#### Q10: How does your automated containment simulation work?
> **Answer:**  
> When containment is triggered via the console (`containment_simulation.ps1` or `/api/containment`), a 3-step defensive remediation sequence executes:
> 1. **Host Isolation:** Deploys an outbound blocking Windows Firewall rule (`SOC_LAB_BLOCK_MALICIOUS_C2_TEST_IP`) blocking destination `203.0.113.50`.
> 2. **Threat Neutralization & Quarantine:** Moves `invoice_malware_sim.exe` from `C:\SOC_Lab_Test` into an isolated vault `C:\SOC_Lab_Quarantine` with a timestamped suffix, neutralizing execution permissions.
> 3. **Artifact Cleanup:** Permanently shreds the simulated ransom note and marks active alert records as `Contained & Mitigated`.

---

### Domain 5: SIEM Operations & Incident Response Lifecycle

#### Q11: Which industry incident response framework did your project adopt?
> **Answer:**  
> We followed the **NIST SP 800-61 Rev. 2** Incident Response Lifecycle:
> 1. **Preparation:** Hardening Sysmon configuration, configuring FIM real-time watches, and deploying rules.
> 2. **Detection & Analysis:** Wazuh Manager correlation, rule evaluation, and dashboard alert generation within 3 seconds.
> 3. **Containment, Eradication & Recovery:** Firewall socket isolation, binary file quarantine, and artifact removal.
> 4. **Post-Incident Activity:** Automated generation of the forensic JSON dossier for audit and lessons learned.

---

#### Q12: What is the difference between an Event, an Alert, and an Incident in your project?
> **Answer:**  
> - **Event:** Any observable occurrence on the laptop (e.g., normal process launch, DNS query, registry read).
> - **Alert:** An event that matches a pre-configured detection rule or threshold requiring analyst attention (e.g., Rule 100003 firing on `invoice_malware_sim.exe`).
> - **Incident:** An alert or series of correlated alerts verified to pose an active threat to system confidentiality, integrity, or availability, requiring immediate triage and containment.

---

### Domain 6: Web Monitoring Platform (CyberSOC Shield)

#### Q13: Why did you build the CyberSOC Shield web console, and how is it architected?
> **Answer:**  
> In enterprise environments, executive stakeholders and L1 triage operators need an intuitive, real-time command center without navigating complex SIEM configuration trees.  
> **Architecture:**
> - **Backend:** Multi-threaded Python server (`ThreadedTCPServer`) with `allow_reuse_address` and caching to guarantee non-blocking responsiveness under high load.
> - **Endpoint Telemetry:** Utilizes native Windows kernel API (`GlobalMemoryStatusEx` via `ctypes`) and `tasklist` to monitor live RAM and active processes with zero performance penalty.
> - **Frontend:** Pure semantic HTML5, Vanilla CSS (cyber glassmorphism theme), and asynchronous JavaScript polling `/api/status`, `/api/telemetry`, and `/api/alerts`.

---

#### Q14: How does your web console avoid race conditions and blocking during attack simulation?
> **Answer:**  
> By utilizing `socketserver.ThreadingMixIn`, each incoming HTTP request (polling status, streaming telemetry, or running simulations) is handled on an isolated worker thread. When a 20-second PowerShell simulation runs, background polling from other tabs continues seamlessly without UI freezing or HTTP request timeouts.

---

### Domain 7: Examiner Trap Questions & Advanced Scenarios

#### Q15: If an attacker gains administrator rights on your laptop, what prevents them from simply stopping the Wazuh Agent or Sysmon?
> **Answer:**  
> If an attacker achieves SYSTEM privilege:
> 1. **Sysmon Driver Protection:** Sysmon operates as a ring-0 kernel driver (`SysmonDrv`), protected by Windows Driver Signature Enforcement.
> 2. **Manager Disconnection Alert:** Wazuh Manager maintains an active keepalive heartbeat. If the agent service terminates or goes silent for more than 10 minutes, Wazuh Manager automatically triggers built-in Rule 504 (`Agent disconnected`), alerting the central SOC team.
> 3. **Forward-Only Architecture:** Agents do not store logs locally; logs are forwarded in real time. Any actions taken *before* disabling the agent are already permanently recorded on the immutable Wazuh Indexer.

---

#### Q16: How would your system handle fileless malware (malware running entirely in memory without writing to disk)?
> **Answer:**  
> While File Integrity Monitoring (FIM) only catches disk modifications, our architecture uses **Sysmon Event ID 1 (Process Creation)** and **Sysmon Event ID 7 (Image Loaded)** to track process injection. Furthermore, Rule 100005 inspects in-memory execution flags like `-EncodedCommand` and script block logging. In an enterprise expansion, Wazuh's integration with Windows AMSI (Antimalware Scan Interface) would inspect decrypted script buffers directly in memory before execution.

---

#### Q17: What is the risk of False Positives in your rules, and how did you minimize them?
> **Answer:**  
> Overly generic rules cause alert fatigue. We minimized false positives by:
> - **Scoped Paths:** Scoping file dropper Rule 100003 and FIM Rule 100004 strictly to the monitored directory (`C:\SOC_Lab_Test\`) rather than the entire disk.
> - **Strict Username Anchoring:** Anchoring brute-force Rule 100006 to `<same_field>win.eventdata.targetUserName</same_field>`, preventing unrelated system account lockouts from triggering false brute-force alerts.
> - **Strict RegEx Modifiers:** Using exact indicator hashes and file basenames with regex boundaries rather than loose wildcard substrings.

---

#### Q18: What is the purpose of the `syscheck` configuration in `ossec.conf`?
> **Answer:**  
> `syscheck` is Wazuh's File Integrity Monitoring (FIM) daemon. In our project, it is configured with:
> ```xml
> <directories check_all="yes" realtime="yes" report_changes="yes">C:\SOC_Lab_Test</directories>
> ```
> This hooks into the Windows ReadDirectoryChangesW API to detect file additions, modifications, permissions tampering, and deletions in real time, calculating SHA256 hashes immediately upon file creation.

---

#### Q19: If the Wazuh server goes down, does the monitored laptop lose all its logs?
> **Answer:**  
> No. The Wazuh Agent has a built-in client buffer (`<client_buffer>` in `ossec.conf`). When the connection to the manager is interrupted, the agent queues up to 5,000 events (configurable) in local memory and disk cache. Once connectivity to Port 1514 is restored, the agent flushes the queued backlog to the Manager without data loss.

---

#### Q20: How do you demonstrate that your detection is fast enough for enterprise standards?
> **Answer:**  
> Our real-time pipeline benchmarks show:
> - **Kernel Detection (Sysmon):** < 15 milliseconds.
> - **Agent Ingestion & Encryption:** < 50 milliseconds.
> - **Manager Rule Matching & OpenSearch Indexing:** < 1.5 seconds.
> - **CyberSOC Shield Live Feed Update:** Reflected on the live dashboard on the very next 3-second polling tick, well within industry Mean Time to Detect (MTTD) benchmarks.

---

## 3. High-Scoring Viva Tips for Students

1. **Start with the Problem:** Do not jump straight to tools. Explain that standard Windows logs cannot detect modern cyberattacks because they lack cryptographic process hashing and network correlation.
2. **Quote Exact Rule Numbers:** Memorize your rule numbers (`100001` to `100006`). Quoting rule IDs and Sysmon Event IDs (1, 3, 11) demonstrates genuine technical ownership.
3. **Use the Live Web Console:** Demonstrate the **CyberSOC Shield** live in your presentation. Click "Launch Test 1", show the terminal output, flip to the Live SOC Monitor, click the alert card to display the raw JSON forensic payload, and click "Trigger Incident Containment" to show the automated remediation.
4. **Reference Industry Standards:** Mention **NIST SP 800-61**, **MITRE ATT&CK Enterprise Matrix**, and **RFC 5737** documentation IPs. Examiners look for adherence to real-world cybersecurity frameworks.
