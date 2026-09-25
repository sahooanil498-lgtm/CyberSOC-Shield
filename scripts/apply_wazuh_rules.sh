#!/bin/bash
# ==============================================================================
# Script: apply_wazuh_rules.sh
# Purpose: Deploys custom detection rules and IOC list on Wazuh Server
# Run on Ubuntu Wazuh Server with sudo
# ==============================================================================

set -e

if [ "$EUID" -ne 0 ]; then
  echo "[-] ERROR: Please run as root: sudo bash apply_wazuh_rules.sh"
  exit 1
fi

echo "=================================================================="
echo "    DEPLOYING CUSTOM WAZUH RULES & IOC LISTS (SOC LAB)           "
echo "=================================================================="

RULES_SRC="./local_rules.xml"
IOCS_SRC="./test_iocs.txt"

# 1. Check source files
if [ ! -f "$RULES_SRC" ]; then
  RULES_SRC="../rules/local_rules.xml"
fi

if [ ! -f "$IOCS_SRC" ]; then
  IOCS_SRC="../iocs/test_iocs.txt"
fi

# 2. Deploy Local Rules
if [ -f "$RULES_SRC" ]; then
  echo "[*] Copying custom detection rules to /var/ossec/etc/rules/local_rules.xml..."
  cp "$RULES_SRC" /var/ossec/etc/rules/local_rules.xml
  chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
  chmod 660 /var/ossec/etc/rules/local_rules.xml
  echo "[+] Custom detection rules deployed."
else
  echo "[-] ERROR: Could not find local_rules.xml!"
  exit 1
fi

# 3. Deploy IOC List
if [ -f "$IOCS_SRC" ]; then
  echo "[*] Copying IOC list to /var/ossec/etc/lists/test_iocs..."
  mkdir -p /var/ossec/etc/lists
  cp "$IOCS_SRC" /var/ossec/etc/lists/test_iocs
  chown -R wazuh:wazuh /var/ossec/etc/lists
  chmod 660 /var/ossec/etc/lists/test_iocs
  echo "[+] IOC list deployed."
fi

# 4. Test Wazuh Configuration & Rule Syntax
echo ""
echo "[*] Testing rule syntax with wazuh-analysisd..."
/var/ossec/bin/wazuh-analysisd -t
echo "[+] Rule syntax validation PASSED!"

# 5. Restart Wazuh Manager
echo ""
echo "[*] Restarting wazuh-manager service to apply new detection rules..."
systemctl restart wazuh-manager

if systemctl is-active --quiet wazuh-manager; then
  echo "[+] Wazuh Manager is active and monitoring with NEW rules!"
else
  echo "[-] Wazuh Manager failed to restart. Check logs: journalctl -u wazuh-manager -n 50"
  exit 1
fi

echo "=================================================================="
echo " Detection Rules (100001 - 100006) are now LIVE on Wazuh SIEM!    "
echo "=================================================================="
