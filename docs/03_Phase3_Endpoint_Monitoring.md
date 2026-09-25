# PHASE 3: Endpoint Monitoring & Telemetry Enrichment Guide

---

## 1. Overview of Phase 3
In this phase, we transform our basic Windows endpoint into a high-visibility, SOC-grade monitored sensor. We will:
1. Understand why default Windows logging is insufficient for threat detection.
2. Install and configure **Microsoft Sysmon** to capture deep telemetry (process trees, command lines, hashes).
3. Configure **Wazuh Agent** to forward Sysmon and PowerShell event channels to the Wazuh Manager.
4. Enable **File Integrity Monitoring (FIM)** in real-time on a designated lab directory (`C:\SOC_Lab_Test`).
5. Verify that high-fidelity telemetry is flowing into the Wazuh SIEM.

---

## 2. Why Sysmon? (Windows Event Log vs Sysmon)

In standard Windows logging (Security Log), when an application runs, **Event ID 4688** is generated. However, by default, it does **not** record the full command-line arguments, does **not** calculate cryptographic file hashes (MD5/SHA256), and does not record network socket connections initiated by scripts.

| Feature | Standard Windows Event Log | Microsoft Sysmon |
| :--- | :--- | :--- |
| **Process Creation** | Event ID 4688 (basic info only) | **Event ID 1** (Full CommandLine, ProcessGuid, ParentProcess, Hashes) |
| **Cryptographic Hashes** | ❌ None | ✅ MD5, SHA256 generated on-the-fly |
| **Network Connections** | ❌ None (unless deep firewall audit is enabled) | **Event ID 3** (Source/Dest IP, Port, Process Name) |
| **File Creation Tracking** | Event ID 4663 (very noisy) | **Event ID 11** (Clean target filename and creating process) |
| **DNS Query Logging** | ❌ None | **Event ID 22** (Target domain queried by process) |

> [!IMPORTANT]
> Without Sysmon, a SOC analyst cannot match IOC hashes (like known malware SHA256) or see if PowerShell ran an encoded script. Sysmon provides the "ground truth" needed for detection.

---

## 3. Step 1: Installing and Configuring Sysmon on Windows

### Option A: Automated Script (Fastest & Recommended)
We provided [install_sysmon.ps1](file:///d:/Cyber%20project/scripts/install_sysmon.ps1).
1. On your Windows VM, open **PowerShell as Administrator**.
2. Run:
```powershell
powershell -ExecutionPolicy Bypass -File "d:\Cyber project\scripts\install_sysmon.ps1"
```
This automatically downloads the latest Sysmon from Microsoft, applies our custom [sysmonconfig.xml](file:///d:/Cyber%20project/configs/sysmonconfig.xml), and starts the service.

---

### Option B: Manual Installation (Step-by-Step for College Demonstration)
If you need to show manual installation steps to your professor:

1. **Download Sysmon:**
   - Download `Sysmon.zip` from Microsoft Docs (Sysinternals).
   - Extract it to `C:\Tools\Sysmon\`.

2. **Prepare Configuration File:**
   - Copy [sysmonconfig.xml](file:///d:/Cyber%20project/configs/sysmonconfig.xml) to `C:\Tools\Sysmon\sysmonconfig.xml`.

3. **Install the Sysmon Service and Driver:**
   - In PowerShell (Run as Administrator):
   ```powershell
   cd C:\Tools\Sysmon
   .\Sysmon64.exe -accepteula -i sysmonconfig.xml
   ```
   *Explanation:*
   - `-accepteula`: Automatically accepts the Microsoft EULA.
   - `-i sysmonconfig.xml`: Installs the kernel-mode driver (`SysmonDrv`) and user-mode service with your configuration filtering rules.

4. **Verify Sysmon is Working:**
   - Run: `Get-Service Sysmon64` (Status should be `Running`).
   - Open **Windows Event Viewer** (`eventvwr.msc`).
   - Navigate to: **Applications and Services Logs** -> **Microsoft** -> **Windows** -> **Sysmon** -> **Operational**.
   - You should see new events appearing continuously. Click on an Event ID 1 to inspect the command line and hashes.

---

## 4. Step 2: Configuring Wazuh Agent for Sysmon Ingestion

By default, the Wazuh Agent only reads standard Security and System logs. We must instruct it to read the Sysmon event channel.

### Automated Setup:
Run our helper script [configure_wazuh_agent.ps1](file:///d:/Cyber%20project/scripts/configure_wazuh_agent.ps1) in PowerShell (Admin):
```powershell
powershell -ExecutionPolicy Bypass -File "d:\Cyber project\scripts\configure_wazuh_agent.ps1"
```

### Manual Configuration (Understanding the XML):
Open `C:\Program Files (x86)\ossec-agent\ossec.conf` in Notepad (as Administrator).

1. Find the `<ossec_config>` section and add:
```xml
<!-- Ingest Sysmon Operational Logs -->
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>

<!-- Ingest PowerShell Operational Logs -->
<localfile>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```
*Explanation:*
- `<location>`: The exact Windows Event Channel name.
- `<log_format>eventchannel</log_format>`: Tells Wazuh to read modern Windows EVTX XML logs, extracting every structured field (ProcessId, CommandLine, Hashes, ParentImage).

---

## 5. Step 3: Enabling File Integrity Monitoring (FIM)

File Integrity Monitoring uses Wazuh's `syscheck` daemon to take cryptographic snapshots (MD5, SHA1, SHA256) of files and detect changes.

### Configure Monitored Folders:
Inside `C:\Program Files (x86)\ossec-agent\ossec.conf`, locate the `<syscheck>` section:

```xml
<syscheck>
  <disabled>no</disabled>
  <frequency>300</frequency>

  <!-- Real-time monitoring for our lab target folder -->
  <directories check_all="yes" realtime="yes" report_changes="yes">C:\SOC_Lab_Test</directories>

  <!-- Monitor critical Windows hosts file and driver configs -->
  <directories check_all="yes" realtime="yes">C:\Windows\System32\drivers\etc</directories>
</syscheck>
```

### Key Attributes Explained:
- `realtime="yes"`: Uses Windows ReadDirectoryChangesW API to alert within seconds when a file is created, modified, or deleted without waiting for the scheduled scan.
- `check_all="yes"`: Computes MD5, SHA1, and SHA256 hashes, size, permissions, and creation timestamps.
- `report_changes="yes"`: For text files, generates a cryptographic diff showing exactly what lines were added or removed!

### Apply Changes:
Restart the agent service:
```powershell
Restart-Service -Name "WazuhSvc"
```

---

## 6. Step 4: Verification — Confirming Telemetry Flow

### Test 1: Verify Sysmon Ingestion in Wazuh
1. On Windows, open PowerShell and launch any program:
   ```powershell
   notepad.exe
   ```
2. In your host browser, open **Wazuh Dashboard** (`https://<Ubuntu_IP>`).
3. Click (☰) -> **Security events** (or Discover).
4. In the search bar, filter by:
   ```text
   data.win.system.providerName: "Microsoft-Windows-Sysmon"
   ```
5. You will see Sysmon **Event ID 1** records showing:
   - `data.win.eventdata.image`: `C:\Windows\System32\notepad.exe`
   - `data.win.eventdata.hashes`: MD5=..., SHA256=...
   - `data.win.eventdata.parentImage`: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

### Test 2: Verify Real-Time File Integrity Monitoring (FIM)
1. On Windows, create a test file in `C:\SOC_Lab_Test`:
   ```powershell
   "Confidential Company Data" | Out-File -FilePath "C:\SOC_Lab_Test\payroll.txt"
   ```
2. On Wazuh Dashboard:
   - Click (☰) -> **Integrity monitoring**.
   - Go to **Inventory** or **Events**.
   - You will see an alert: **"File 'C:\SOC_Lab_Test\payroll.txt' added to the system"** with Rule ID **550** (FIM file added).

---

## 7. Troubleshooting Common Errors

| Issue | Cause | Fix |
| :--- | :--- | :--- |
| `WazuhSvc` fails to start after editing `ossec.conf` | XML syntax error (e.g. unclosed tag `<localfile>`). | Check XML validity in Notepad++. Revert to backup created by script or check Windows Application log for OSSEC error line. |
| Sysmon events not appearing in Wazuh | Event channel name typo or Sysmon service not running. | Verify `Get-Service Sysmon64` is Running. Ensure channel is exact: `Microsoft-Windows-Sysmon/Operational`. |
| FIM events taking too long to appear | `realtime="yes"` attribute missing from `<directories>` tag. | Ensure `<directories check_all="yes" realtime="yes">C:\SOC_Lab_Test</directories>` is present and agent was restarted. |
