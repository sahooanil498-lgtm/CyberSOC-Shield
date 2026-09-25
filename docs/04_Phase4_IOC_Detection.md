# PHASE 4: IOC Detection & Custom Detection Rules

---

## 1. Overview of Phase 4
In this phase, we implement proactive threat detection capabilities in our SIEM:
1. Understand **Indicators of Compromise (IOCs)** and their role in a SOC.
2. Build an **IOC Threat Intelligence List** for our lab.
3. Write **Custom Wazuh Detection Rules** mapped to the **MITRE ATT&CK Framework**.
4. Deploy the rules and IOC lists to the **Wazuh Manager**.
5. Execute **harmless, controlled security simulations** on the Windows endpoint.
6. Verify high-severity security alerts appearing on the **Wazuh Dashboard**.

---

## 2. What are Indicators of Compromise (IOCs)?

An **Indicator of Compromise (IOC)** is an artifact observed on a network or operating system that indicates, with high confidence, that a security incident or intrusion has occurred.

### The Pyramid of Pain (David Bianco):
Understanding where our IOCs fit is a favorite question in college vivas:
- **Hash Values (Trivial):** SHA256/MD5 (e.g. `4a1b025fbc77...`). If the attacker changes one byte, the hash changes.
- **IP Addresses (Easy):** C2 server IPs (e.g. `203.0.113.50`). Attackers can rotate IPs easily using proxies.
- **Domain Names (Simple):** Fast-flux DNS, phishing domains.
- **Host / Network Artifacts (Annoying):** Dropped file names (e.g. `invoice_malware_sim.exe`), registry keys.
- **Tools (Challenging):** Mimikatz, PowerShell loaders.
- **TTPs (Tough):** Tactics, Techniques, and Procedures (e.g., Living-off-the-Land binaries).

> [!NOTE]
> All test indicators in this lab are **completely harmless**:
> - IPs use the official **RFC 5737** documentation range (`203.0.113.0/24`), which never routes to real computers on the public internet.
> - File hashes correspond to harmless plain text strings created inside our lab.

---

## 3. Our Custom Detection Rules (local_rules.xml)

Custom rules are added to `/var/ossec/etc/rules/local_rules.xml` on the Wazuh Manager. Wazuh assigns IDs `100000+` to custom user rules:

| Rule ID | Severity Level | MITRE ATT&CK | Description | Trigger Event |
| :--- | :--- | :--- | :--- | :--- |
| **100001** | Level 12 (Critical) | `T1071.001` (C2) | Outbound connection to Known Malicious C2 Test IP (`203.0.113.50`) | Sysmon Event ID 3 |
| **100002** | Level 13 (Critical) | `T1204.002` (Execution) | Execution of process matching Known Malicious Test Hash | Sysmon Event ID 1 |
| **100003** | Level 10 (High) | `T1105` (Ingress Transfer) | Suspicious test payload created (`invoice_malware_sim.exe`) | Sysmon Event ID 11 |
| **100004** | Level 11 (High) | `T1486` (Ransomware) | Simulated Ransomware Note created (`test_ransom_note.txt`) | Wazuh FIM (Rule 550 / 554) |
| **100005** | Level 8 (Medium) | `T1059.001` (PowerShell) | Obfuscated Base64 Encoded PowerShell command execution | Sysmon Event ID 1 |
| **100006** | Level 10 (High) | `T1110` (Brute Force) | 3+ failed Windows logins within 60 seconds targeting same account | Windows Event ID 4625 |

---

## 4. Step 1: Deploying Rules & IOCs to Wazuh Manager

You can deploy the rules either using our automated shell script or via the Wazuh Dashboard Web GUI.

### Method A: Via Ubuntu Terminal (Fast & Scripted)
1. On your **Ubuntu Server VM**, copy the rules file:
   ```bash
   sudo nano /var/ossec/etc/rules/local_rules.xml
   ```
2. Paste the contents of [local_rules.xml](file:///d:/Cyber%20project/rules/local_rules.xml).
3. Test your rule syntax:
   ```bash
   sudo /var/ossec/bin/wazuh-analysisd -t
   ```
   *Expected Output:* `Configuration check successful! No errors found.`
4. Restart the Wazuh Manager:
   ```bash
   sudo systemctl restart wazuh-manager
   ```

### Method B: Via Wazuh Web Dashboard (Visual UI)
1. Open Wazuh Dashboard in your browser (`https://<Ubuntu_IP>`).
2. Click the top-left menu (☰) -> **Management** -> **Rules**.
3. Click **Manage rules files** -> Click **local_rules.xml**.
4. Click the Edit icon (pencil) on the top right.
5. Paste the XML content from [local_rules.xml](file:///d:/Cyber%20project/rules/local_rules.xml).
6. Click **Save** -> Click **Restart manager**.

---

## 5. Step 2: Executing Safe Threat Simulations

Now switch to your **Windows Endpoint VM** to trigger the detections safely.

### Run the Simulator Script:
1. Open **PowerShell (Run as Administrator)**.
2. Run our automated test script:
   ```powershell
   powershell -ExecutionPolicy Bypass -File "d:\Cyber project\scripts\simulate_ioc_event.ps1"
   ```
3. The script will safely execute 4 test scenarios:
   - **Test 1:** Sends an outbound TCP SYN packet to RFC test IP `203.0.113.50:443`.
   - **Test 2:** Drops dummy text inside `C:\SOC_Lab_Test\invoice_malware_sim.exe`.
   - **Test 3:** Drops simulated educational notice `C:\SOC_Lab_Test\test_ransom_note.txt`.
   - **Test 4:** Executes a safe `Write-Host` command obfuscated in Base64 encoding.

---

## 6. Step 3: Verification on Wazuh Dashboard

1. In your host browser, open **Wazuh Dashboard**.
2. Click (☰) -> **Security events**.
3. In the search filter bar at the top, enter:
   ```text
   rule.id: (100001 or 100003 or 100004 or 100005)
   ```
4. Click **Apply**.
5. You will see 4 distinct security alerts:
   - 🔴 **Rule 100001 (Level 12):** `SOC-LAB ALERT [CRITICAL]: Outbound network connection to Known Malicious C2 Test IP (203.0.113.50)`
   - 🟠 **Rule 100003 (Level 10):** `SOC-LAB ALERT [MEDIUM]: Suspicious test dropper or payload created on disk: C:\SOC_Lab_Test\invoice_malware_sim.exe`
   - 🔴 **Rule 100004 (Level 11):** `SOC-LAB ALERT [HIGH]: Potential Ransomware Indicator - Ransom note dropped: C:\SOC_Lab_Test\test_ransom_note.txt`
   - 🟡 **Rule 100005 (Level 8):** `SOC-LAB ALERT [MEDIUM]: Obfuscated or Base64 Encoded PowerShell command line detected`

---

## 7. Troubleshooting Common Errors

| Issue | Cause | Fix |
| :--- | :--- | :--- |
| `wazuh-analysisd -t` fails with XML syntax error | Missing closing tag or unescaped character (like `&` or `<`) in `local_rules.xml`. | Check the line number mentioned in the error. Ensure regex special characters like `.` are escaped as `\.` |
| Alert 100001 does not fire on C2 connection | Sysmon Event ID 3 is disabled or filtered out. | Check `eventvwr.msc` on Windows -> Microsoft/Windows/Sysmon/Operational. Verify Event ID 3 appears for powershell.exe connecting to `203.0.113.50`. |
| Alert 100004 does not fire on ransom note | FIM scan interval has not reached or directory path is not set to `realtime="yes"`. | Ensure `C:\SOC_Lab_Test` has `realtime="yes"` in `ossec.conf` on the Windows agent. |
