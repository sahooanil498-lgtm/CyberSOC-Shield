# PHASE 7: Wazuh Dashboard Views & Visualizations Guide

---

## 1. Overview of Phase 7
In a production SOC, analysts do not read raw log lines one by one. Instead, they rely on **SIEM Dashboards** and **Data Visualizations** to spot anomalous spikes, monitor high-severity threats, and track endpoint health.

In this phase, we build a dedicated SOC Dashboard titled:  
**`"SOC Lab - Threat Detection & IOC Monitoring Dashboard"`**

It incorporates 7 specialized views and visualizations:
1. **Security Alerts Stream** (Filtered for actionable intelligence)
2. **Severity Distribution** (Pie / Donut Chart)
3. **Top Triggered Detection Rules** (Horizontal Bar Chart)
4. **Affected Endpoint Activity** (Host-level Drilldown)
5. **IOC Detections Feed** (Live matches on Rule 100001 - 100005)
6. **Authentication & Brute-Force Events** (Event 4624 / 4625)
7. **File Integrity Monitoring (FIM)** (File additions, changes, deletions)

---

## 2. Master Dashboard Layout Mockup

```
+-----------------------------------------------------------------------------------------+
|                  SOC LAB: THREAT DETECTION & IOC MONITORING DASHBOARD                   |
+------------------------------------+----------------------------------------------------+
|  [METRIC CARD: CRITICAL ALERTS]    |  [PIE CHART: ALERTS BY SEVERITY]                   |
|              4                     |   - Level 12 (Critical): 25%                       |
|   (Level 12+ Requiring Triage)     |   - Level 10-11 (High):  50%                       |
|                                    |   - Level 8 (Medium):    25%                       |
+------------------------------------+----------------------------------------------------+
|  [BAR CHART: TOP 5 TRIGGERED DETECTION RULES]                                           |
|  Rule 100001: Outbound C2 Connection  [████████████████████] (Count: 1)                 |
|  Rule 100004: Ransomware Note Dropped [████████████████████] (Count: 1)                 |
|  Rule 100003: Suspicious Dropper      [████████████████████] (Count: 1)                 |
|  Rule 100005: Encoded PowerShell      [████████████████████] (Count: 1)                 |
|  Rule 550: FIM File Added             [██████████████████████████████] (Count: 2)       |
+-----------------------------------------------------------------------------------------+
|  [DATA TABLE: LIVE IOC DETECTIONS FEED]                                                 |
|  Timestamp   | Endpoint         | Rule ID | Severity | Description                      |
|  10:35:12    | WIN-ENDPOINT-01  | 100001  | Level 12 | Outbound connection to C2 IP     |
|  10:35:13    | WIN-ENDPOINT-01  | 100003  | Level 10 | Suspicious test dropper created  |
|  10:35:14    | WIN-ENDPOINT-01  | 100004  | Level 11 | Potential Ransomware Indicator   |
|  10:35:15    | WIN-ENDPOINT-01  | 100005  | Level 8  | Obfuscated Base64 PowerShell     |
+-----------------------------------------------------------------------------------------+
|  [FIM EVENTS MONITOR]                     |  [AUTHENTICATION MONITOR]                   |
|  - C:\SOC_Lab_Test\invoice_malware_sim.exe|  - User: socadmin (Logon Success 4624)      |
|  - C:\SOC_Lab_Test\test_ransom_note.txt   |  - User: attacker (Failed Logon 4625)       |
+-------------------------------------------+---------------------------------------------+
```

---

## 3. Step-by-Step: Creating the 7 Views & Queries

All queries use **KQL (Kibana/OpenSearch Query Language)** in the top search bar of the Wazuh Dashboard.

### View 1: Security Alerts (Noise-Filtered)
- **Goal:** Display all alerts with Severity Level 8 or higher (ignoring low-severity informational noise).
- **KQL Query:**
  ```text
  rule.level >= 8
  ```
- **Selected Table Columns:** `timestamp`, `agent.name`, `rule.id`, `rule.level`, `rule.description`.

---

### View 2: Severity Distribution (Pie Chart)
- **Goal:** Visual breakdown showing the proportion of Low, Medium, High, and Critical alerts.
- **How to create:**
  1. Open menu (☰) -> **OpenSearch Dashboards** -> **Visualize**.
  2. Click **Create Visualization** -> Select **Pie Chart**.
  3. Source: Select `wazuh-alerts-*`.
  4. Under **Buckets**, click **Split slices** -> Aggregation: **Terms**.
  5. Field: `rule.level`. Order by: metric count.
  6. Click **Update** -> Save as `"Alerts by Severity Level"`.

---

### View 3: Top Triggered Rules (Horizontal Bar Chart)
- **Goal:** Quickly identify which specific threats are recurring most frequently.
- **How to create:**
  1. Click **Create Visualization** -> Select **Horizontal Bar**.
  2. Y-Axis: Aggregation = **Terms**, Field = `rule.description.keyword`, Size = `5`.
  3. X-Axis: Aggregation = **Count**.
  4. Click **Update** -> Save as `"Top 5 Triggered Security Rules"`.

---

### View 4: Affected Endpoint Activity
- **Goal:** Filter all events specifically for our Windows target machine.
- **KQL Query:**
  ```text
  agent.name: "WIN-ENDPOINT-01"
  ```
- **Use Case:** When investigating an active incident on a specific laptop or server, this isolates that host's telemetry stream.

---

### View 5: Live IOC Detections Feed (Data Table)
- **Goal:** An alert table showing only our custom IOC detections (Rules 100001 - 100005).
- **KQL Query:**
  ```text
  rule.id: (100001 or 100002 or 100003 or 100004 or 100005)
  ```
- **How to create Data Table:**
  1. Select **Data Table** visualization.
  2. Add split rows: `rule.id`, `rule.description.keyword`, `agent.name.keyword`.
  3. Save as `"Active IOC Detections Feed"`.

---

### View 6: Authentication Events (Logon Success / Failed)
- **Goal:** Track user logons and brute-force attempts.
- **KQL Query:**
  ```text
  data.win.system.eventID: (4624 or 4625) or rule.groups: "authentication_failed"
  ```
- **Displayed Fields:**
  - `data.win.eventdata.targetUserName` (Account attempted)
  - `data.win.eventdata.ipAddress` (Caller IP)
  - `data.win.system.eventID` (4624 = Success, 4625 = Failure)

---

### View 7: File Integrity Monitoring (FIM) Events
- **Goal:** Real-time visibility into changes in monitored directories.
- **KQL Query:**
  ```text
  rule.groups: "syscheck" or syscheck.path: *
  ```
- **Displayed Fields:**
  - `syscheck.path` (File path changed)
  - `syscheck.event` (added / modified / deleted)
  - `syscheck.sha256_after` (New cryptographic hash)
  - `syscheck.size_after` (File size)

---

## 4. Step-by-Step: Assembling the Master Dashboard

1. In Wazuh Dashboard, open menu (☰) -> **OpenSearch Dashboards** -> **Dashboard**.
2. Click **Create new dashboard**.
3. Click **Add an existing** (or **Add panel**).
4. Select each saved visualization:
   - `[Metric] Critical Threat Alerts`
   - `[Pie Chart] Alerts by Severity Level`
   - `[Bar Chart] Top 5 Triggered Security Rules`
   - `[Data Table] Active IOC Detections Feed`
5. Drag and resize the panels to match our layout mockup in Section 2.
6. Set the top-right time selector to **"Last 24 hours"** and Auto-refresh to **"10 seconds"**.
7. Click **Save** in the top navigation bar and title it:
   **`SOC Lab - Threat Detection & IOC Monitoring Dashboard`**
