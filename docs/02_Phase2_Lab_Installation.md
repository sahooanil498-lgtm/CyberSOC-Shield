# PHASE 2: Lab Installation & Endpoint Enrollment Guide

---

## 1. Overview of Phase 2
In this phase, we will:
1. Create and configure the **Ubuntu Server VM** (Wazuh SIEM).
2. Install the **Wazuh Central Components** (Manager, Indexer, Dashboard) using the official installation assistant.
3. Access and verify the **Wazuh Web Dashboard** from your host browser.
4. Install and configure the **Wazuh Agent** on your **Windows Endpoint VM**.
5. Connect the Windows endpoint to the Wazuh Manager and verify telemetry ingestion.

---

## 2. Step 1: Setting Up the Ubuntu Server VM

### In VirtualBox / VMware:
1. **Create New VM:**
   - **Name:** `Wazuh-SIEM-Server`
   - **Type:** Linux
   - **Version:** Ubuntu (64-bit)
   - **Base Memory (RAM):** `4096 MB` (4 GB minimum; 6 GB if host has 16 GB+)
   - **Processors:** `2 vCPUs`
   - **Virtual Hard Disk:** `30 GB` (Dynamically allocated, VDI/VMDK)
2. **Network Configuration (Crucial):**
   - Go to VM **Settings** -> **Network**.
   - Set **Attached to:** `Bridged Adapter` (Select your active Wi-Fi or Ethernet card)
     *OR*
   - Set **Attached to:** `NAT Network` (if you want an isolated private subnet, e.g. `192.168.100.0/24`).
   - *Recommendation for beginners:* **Bridged Adapter** is easiest because your host computer browser can directly open `https://<Ubuntu-IP>`.
3. **Install Ubuntu Server 22.04 LTS:**
   - Attach the Ubuntu Server 22.04 ISO to the virtual optical drive and start the VM.
   - Select language: **English**.
   - Network connections: Let it obtain an IP via DHCP automatically (note this IP).
   - Storage configuration: Use an entire disk (default options, press Done).
   - Profile setup:
     - Your name: `socadmin`
     - Server name: `wazuh-server`
     - Username: `socadmin`
     - Password: `Password123!` (choose something memorable)
   - SSH setup: Check **[X] Install OpenSSH server** (makes it easy to copy-paste commands from your host).
   - Finish installation, reboot the VM, and remove the ISO when prompted.

---

## 3. Step 2: Preparing Ubuntu & Installing Wazuh All-in-One

Log into your Ubuntu terminal with your username and password.

### 2.1 Find your Ubuntu Server IP Address
Run:
```bash
hostname -I
```
*Explanation:* This displays your server's IP address (e.g., `192.168.1.150`). Note this down; you will use it to access the web interface and configure the Windows agent.

### 2.2 Update System Packages
Run:
```bash
sudo apt update && sudo apt upgrade -y
```
*Explanation:* Updates package lists and upgrades existing system software to prevent compatibility errors.

### 2.3 Install Necessary Dependencies
Run:
```bash
sudo apt install -y curl apt-transport-https lsb-release gnupg tar
```
*Explanation:* `curl` downloads installation scripts and packages securely from the internet.

### 2.4 Run the Wazuh Automated Installation Assistant
Wazuh provides an official all-in-one script that automatically installs and configures the Indexer, Manager, Dashboard, and generates internal SSL certificates.

Run:
```bash
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```
*Explanation:*
- `curl -sO ...`: Downloads `wazuh-install.sh` quietly and saves it locally.
- `sudo bash ./wazuh-install.sh -a`: Executes the installation in all-in-one mode (`-a`).

> [!NOTE]
> This process takes **5 to 10 minutes** depending on your internet speed and processor.
> **DO NOT interrupt the terminal.**

### 2.5 Save the Credentials Output
When the installation completes, the script will output something like this on your screen:
```
INFO: --- Summary ---
INFO: Wazuh indexer installation finished.
INFO: Wazuh manager installation finished.
INFO: Wazuh dashboard installation finished.

The password for 'admin' user is: <YOUR_GENERATED_PASSWORD>
```
The assistant also creates a file named `wazuh-passwords.txt` in your current directory.
To view it anytime, run:
```bash
sudo tar -O -xvf wazuh-install-files.tar wazuh-passwords.txt
```
or inspect:
```bash
cat wazuh-passwords.txt
```

---

## 4. Step 3: Verifying Wazuh Services & Accessing Web Dashboard

### 4.1 Verify Services are Active and Running
Check the status of each component on Ubuntu:
```bash
sudo systemctl status wazuh-manager --no-pager
sudo systemctl status wazuh-indexer --no-pager
sudo systemctl status wazuh-dashboard --no-pager
```
*What to look for:* Each service should show **`Active: active (running)`** in green text.

### 4.2 Configure Firewall (UFW)
Ensure required communication ports are open on Ubuntu:
```bash
sudo ufw allow 443/tcp
sudo ufw allow 1514/tcp
sudo ufw allow 1515/tcp
sudo ufw enable
```
*Port Explanation:*
- `443/tcp`: Wazuh Web Dashboard (HTTPS).
- `1514/tcp`: Agent-to-Manager secure event communication.
- `1515/tcp`: Agent registration and enrollment service.

### 4.3 Log into Wazuh Dashboard from Host Browser
1. Open Google Chrome, Firefox, or Microsoft Edge on your host computer.
2. In the URL bar, type:
   ```
   https://<YOUR_UBUNTU_IP>
   ```
   *(Example: `https://192.168.1.150`)*
3. **Bypass the SSL Warning:** Because Wazuh uses a self-signed security certificate for local lab use, your browser will warn: *"Your connection isn't private"* or *"Potential Security Risk"*.
   - Click **Advanced** -> Click **Proceed to `<IP>` (unsafe)** or **Accept the Risk and Continue**.
4. **Log In:**
   - **Username:** `admin`
   - **Password:** `<Generated_Password_From_Step_3.5>`
5. You should now see the Wazuh Dashboard homepage!

---

## 5. Step 4: Installing and Enrolling Wazuh Agent on Windows Endpoint

Now switch to your **Windows Endpoint Virtual Machine**.

### 5.1 Test Connectivity from Windows to Ubuntu
1. Open PowerShell on Windows as Administrator.
2. Verify you can reach the Wazuh Server port:
```powershell
Test-NetConnection -ComputerName <YOUR_UBUNTU_IP> -Port 1514
```
*Expected Result:* `TcpTestSucceeded : True`.

### 5.2 Download the Wazuh Agent
In Windows PowerShell (Run as Administrator), run:
```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.0-1.msi -OutFile "$env:TEMP\wazuh-agent.msi"
```
*Explanation:* Downloads the official Windows installer `.msi` file to the temporary folder.

### 5.3 Install and Register the Agent with Wazuh Manager
Run the installer command from PowerShell, replacing `<YOUR_UBUNTU_IP>` with your Ubuntu VM's actual IP:
```powershell
msiexec.exe /i "$env:TEMP\wazuh-agent.msi" /q WAZUH_MANAGER="<YOUR_UBUNTU_IP>" WAZUH_REGISTRATION_SERVER="<YOUR_UBUNTU_IP>" WAZUH_AGENT_NAME="WIN-ENDPOINT-01"
```
*Parameter Breakdown:*
- `/i ... /q`: Install silently in the background.
- `WAZUH_MANAGER="..."`: Points the agent to the Ubuntu Wazuh server to stream security events.
- `WAZUH_REGISTRATION_SERVER="..."`: Specifies where the agent registers its cryptographic keys.
- `WAZUH_AGENT_NAME="WIN-ENDPOINT-01"`: Friendly hostname displayed on the SIEM dashboard.

### 5.4 Start the Wazuh Agent Service
Run in PowerShell:
```powershell
NET START WazuhSvc
```
*Expected output:* `The Wazuh service was started successfully.`

---

## 6. Step 5: Verification — Confirming Agent is Active & Ingesting Logs

### 6.1 Check Agent Connection Status from Ubuntu CLI
Back in your Ubuntu terminal, run:
```bash
sudo /var/ossec/bin/agent_control -l
```
*Expected Output:*
```
Wazuh agent_control. List of available agents:
   ID: 000, Name: wazuh-server (server), IP: 127.0.0.1, Active/Local
   ID: 001, Name: WIN-ENDPOINT-01, IP: any, Active
```
Notice `WIN-ENDPOINT-01` has status **Active**!

### 6.2 Check Agent Connection Status on Wazuh Dashboard
1. Go back to your browser on `https://<YOUR_UBUNTU_IP>`.
2. Click the top-left menu icon (☰) -> Navigate to **Server Management** -> **Endpoints Summary** (or **Agents**).
3. You will see:
   - **Total Agents:** `1`
   - **Active Agents:** `1` (Green indicator)
   - Agent Name: `WIN-ENDPOINT-01`
   - OS: `Windows`

### 6.3 Verify Log Ingestion in Real-Time
1. In the Wazuh Dashboard, click the top-left menu (☰) -> **Security events**.
2. Set the time range to **"Last 15 minutes"**.
3. You will see incoming security events from your Windows machine (logon events, service starts, system events).

---

## 7. Troubleshooting Common Errors

| Issue | Cause | Solution |
| :--- | :--- | :--- |
| `curl: (7) Failed to connect to localhost port 9200` | Wazuh Indexer ran out of memory during initialization. | Check `free -m`. If free RAM is < 1GB, add a swap file: `sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile`. Then restart indexer: `sudo systemctl restart wazuh-indexer`. |
| Windows Agent status shows `Never connected` | Port 1514/1515 blocked or wrong IP given. | 1. Check Ubuntu firewall: `sudo ufw status`.<br>2. On Windows, check `C:\Program Files (x86)\ossec-agent\ossec.log` to see the exact connection error message. |
| Cannot open `https://<Ubuntu_IP>` in host browser | VM network is set to standard NAT without port forwarding. | Change VM network adapter in VirtualBox/VMware settings to **Bridged Adapter**, reboot Ubuntu, and re-check IP with `hostname -I`. |
