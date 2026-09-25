# PHASE 1: Project Setup & Architecture Blueprint

## 1. Project Objective
The objective of this project is to build a practical, isolated **Security Operations Center (SOC) lab** to simulate, detect, investigate, and document security threats using **Wazuh SIEM**. 

As a defensive cybersecurity project, it demonstrates the real-world workflow of a **Tier-1 / Tier-2 SOC Analyst**:
1. **Telemetry Ingestion:** Collecting endpoint activity (process creation, file modifications, authentication attempts) via Sysmon and Windows Event Logs.
2. **Detection & Correlation:** Using Wazuh's rules engine and threat intelligence (IOC matching) to flag anomalies and suspicious behaviors.
3. **Alert Investigation:** Analyzing the timeline, parent-child processes, hashes, and network metadata behind an alert.
4. **Defensive Response & Reporting:** Recommending containment/remediation steps and documenting evidence for audit and academic evaluation.

---

## 2. Lab Architecture & Data Flow

```
+--------------------------------------------------------------------------------+
|                                HOST COMPUTER                                   |
|                        (Hypervisor: VirtualBox / VMware)                       |
|                                                                                |
|   +------------------------------------+   +-------------------------------+   |
|   |         Ubuntu Server VM           |   |       Windows Endpoint VM     |   |
|   |          (Wazuh Server)            |   |       (Monitored System)      |   |
|   |                                    |   |                               |   |
|   |  - Wazuh Manager (Port 1514/1515)  |   |  - Wazuh Agent (Service)      |   |
|   |  - Wazuh Indexer (Port 9200)       |   |  - Microsoft Sysmon           |   |
|   |  - Wazuh Dashboard (Port 443/Web)  |   |  - Windows Event Log System   |   |
|   |                                    |   |  - Monitored Folders (FIM)    |   |
|   |        IP: 192.168.x.10            |   |       IP: 192.168.x.20        |   |
|   +------------------^-----------------+   +---------------+---------------+   |
|                      |                                     |                   |
|                      |        Secure Log Traffic (Port 1514) |                 |
|                      +-------------------------------------+                   |
|                                                                                |
|                        Virtual NAT Network (Isolated)                          |
+--------------------------------------------------------------------------------+
                                       |
                   Browser Access (Host Browser -> https://192.168.x.10)
```

### Data Flow Explanation:
1. An action occurs on the **Windows Endpoint** (e.g., file created in a critical directory, suspicious process launched, test IOC touched).
2. **Sysmon** captures granular details (Process GUID, CommandLine, ParentProcess, Hashes like MD5/SHA256).
3. The **Wazuh Agent** reads the event logs and file changes, encrypts the data, and sends it over port `1514/TCP` to the **Wazuh Manager**.
4. The **Wazuh Manager** decodes the event, compares it against detection rules and IOC lists.
5. If a match occurs, an **Alert** is triggered, enriched, and stored in the **Wazuh Indexer** (Elasticsearch/OpenSearch engine).
6. The analyst accesses the **Wazuh Dashboard** via web browser to review alerts, drill down into evidence, and initiate investigation.

---

## 3. System Requirements (Hardware Sizing)

To run both virtual machines smoothly on your host machine:

### Host Computer Requirements:
- **CPU:** 4 physical cores (Intel i5/i7/Ryzen 5 or higher) with Virtualization (VT-x / AMD-V) enabled in BIOS.
- **RAM:** Minimum 16 GB RAM recommended.
  - *If you have 8 GB RAM:* We will use lightweight resource profiles (4 GB for Ubuntu, 3 GB for Windows) and close host background apps.
- **Storage:** At least 50 GB free disk space (preferably SSD).

### Virtual Machine Sizing Breakdown:
| Virtual Machine | Operating System | vCPUs | RAM Allocated | Disk Space | Purpose |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **VM 1: Wazuh All-in-One** | Ubuntu Server 22.04 LTS | 2 Cores | 4 GB - 6 GB | 30 GB | Manager, Indexer, Dashboard |
| **VM 2: Endpoint** | Windows 10/11 or Win Server 2022 | 2 Cores | 3 GB - 4 GB | 25 GB - 30 GB | Wazuh Agent, Sysmon, Lab Target |

---

## 4. Software Requirements & Official Download Sources

1. **Hypervisor (Choose one):**
   - **Oracle VirtualBox** (Version 7.0+): Free & Open Source.
   - **VMware Workstation Pro / Player**: Now free for personal use.

2. **Server OS Image:**
   - **Ubuntu Server 22.04.4 LTS (64-bit)** `.iso`
   - *Why 22.04 LTS?* It is the most stable and natively supported platform for the Wazuh all-in-one assistant.

3. **Endpoint OS Image (Choose one):**
   - **Windows 10 / 11 Enterprise (Evaluation ISO)** directly from Microsoft Evaluation Center (90-day free trial), OR
   - A pre-built Windows developer VM image from Microsoft.

4. **Monitoring Tools & Agent Software:**
   - **Wazuh SIEM**: 4.8.x or 4.9.x (Installed via official script on Ubuntu).
   - **Microsoft Sysinternals Sysmon**: Sysmon64.exe (Installed on Windows).
   - **Sysmon Configuration Template**: SwiftOnSecurity `sysmonconfig-export.xml` (Best practice rule baseline for college labs).

---

## 5. Role of Every Component Explained

| Component | Layer | Detailed Role in SOC Architecture |
| :--- | :--- | :--- |
| **Wazuh Agent** | Endpoint Agent | Runs as a background service (`WazuhSvc.exe`) on Windows. Monitors events, registry, files, and transmits telemetry back to Manager over an encrypted channel. |
| **Microsoft Sysmon** | Endpoint Sensor | A Windows system service and device driver that logs detailed process creations, network connections, file creation time changes, and process tampering into Windows Event Logs (`Microsoft-Windows-Sysmon/Operational`). |
| **Wazuh Manager** | Brain / SIEM Engine | Receives raw telemetry from agents, parses data using decoders, evaluates events against rulesets, handles alert generation, and coordinates FIM scans. |
| **Wazuh Indexer** | Database / Storage | High-performance search and analytics engine (based on OpenSearch). Indexes security alerts as JSON documents for ultra-fast querying and long-term retention. |
| **Wazuh Dashboard** | User Interface | Web interface for SOC analysts. Visualizes alerts, displays real-time charts, provides investigative search filters, and rule management. |
| **File Integrity Monitoring (FIM)** | Feature / Engine | Wazuh's `syscheck` module that calculates cryptographic hashes (MD5, SHA1, SHA256) of critical directories to detect unauthorized file creations, deletions, or modifications. |
| **CDB Lists (IOC Matching)** | Threat Intel | Constant Database (CDB) files on Wazuh Manager used for ultra-fast lookup of known malicious IP addresses, domain names, and file hashes. |

---

## 6. Virtual Networking Recommendation

For security and lab realism, the VMs should be placed on an isolated internal network:
- **VirtualBox:** Use **NAT Network** (e.g., `192.168.100.0/24`) with DHCP enabled. This allows both VMs to talk to each other and access the internet for updates, while remaining isolated from your home LAN.
- Alternatively, use **Bridged Adapter** if you are on a trusted home Wi-Fi and want direct IP access from your host machine browser.

---

## 7. Next Step Verification Checklist
Before we begin **Phase 2 (Lab Installation)**, please verify:
- [ ] VirtualBox or VMware is installed on your computer.
- [ ] You have downloaded the **Ubuntu Server 22.04 LTS ISO**.
- [ ] You have a Windows 10/11 ISO or installed Windows VM ready.
- [ ] You have checked your system RAM to confirm whether we should configure 8GB total VM allocation or 10GB+ VM allocation.
