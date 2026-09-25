#!/bin/bash
# ==============================================================================
# Script: setup_wazuh_server.sh
# Purpose: Automated Wazuh SIEM All-in-One Server Setup for Ubuntu 22.04 LTS
# Project: IOC / Security Alert Detection & Investigation (College SOC Lab)
# ==============================================================================

set -e

# 1. Check Root Privileges
if [ "$EUID" -ne 0 ]; then
  echo "[-] ERROR: Please run this script with sudo or as root: sudo bash setup_wazuh_server.sh"
  exit 1
fi

echo "=================================================================="
echo "    WAZUH SIEM ALL-IN-ONE AUTOMATED INSTALLER (SOC LAB)           "
echo "=================================================================="

# 2. Get Server IP Address
IP_ADDR=$(hostname -I | awk '{print $1}')
echo "[*] Detected Server IP Address: $IP_ADDR"

# 3. Memory & Resource Check
TOTAL_MEM=$(free -m | awk '/^Mem:/{print $2}')
echo "[*] Detected Total RAM: ${TOTAL_MEM}MB"

if [ "$TOTAL_MEM" -lt 3500 ]; then
  echo "[!] WARNING: System RAM is under 4GB. Adding a 2GB swap file to prevent out-of-memory crashes..."
  if [ ! -f /swapfile ]; then
    fallocate -l 2G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
    echo "[+] Swap file created and enabled successfully."
  else
    echo "[*] Swap file already exists."
  fi
fi

# 4. System Update and Prerequisites
echo ""
echo "[*] Updating package repository lists..."
apt-get update -y
apt-get install -y curl apt-transport-https lsb-release gnupg tar ufw

# 5. Configure Firewall Rules (UFW)
echo ""
echo "[*] Configuring UFW firewall rules for Wazuh ports..."
ufw allow 22/tcp comment 'SSH'
ufw allow 443/tcp comment 'Wazuh Dashboard HTTPS'
ufw allow 1514/tcp comment 'Wazuh Agent Communication'
ufw allow 1515/tcp comment 'Wazuh Agent Registration'
ufw --force enable
echo "[+] Firewall rules configured and active."

# 6. Download and Run Official Wazuh Installation Assistant
echo ""
echo "[*] Downloading official Wazuh 4.9 installation assistant..."
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh

echo "[*] Starting Wazuh All-in-One installation..."
echo "[*] NOTE: This takes 5-8 minutes. Do not interrupt this process!"
bash ./wazuh-install.sh -a

# 7. Verification of Running Services
echo ""
echo "[*] Verifying installed services status..."
for svc in wazuh-indexer wazuh-manager wazuh-dashboard; do
  if systemctl is-active --quiet "$svc"; then
    echo "[+] Service $svc is RUNNING!"
  else
    echo "[-] Service $svc is NOT running. Check logs using: journalctl -u $svc -n 50"
  fi
done

# 8. Print Access Details
echo ""
echo "=================================================================="
echo "                   INSTALLATION COMPLETE!                        "
echo "=================================================================="
echo "Access the Wazuh Web Dashboard at:"
echo "👉 https://$IP_ADDR"
echo ""
echo "To view your admin credentials, run:"
echo "👉 cat wazuh-passwords.txt"
echo "=================================================================="
