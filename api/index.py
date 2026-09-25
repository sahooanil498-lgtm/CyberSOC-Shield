# ==============================================================================
# CyberSOC Shield - Vercel Serverless API Function
# Provides full-stack SIEM simulation, static malware analysis, telemetry & activity stream
# ==============================================================================

from http.server import BaseHTTPRequestHandler
import json
import urllib.parse
import os
import hashlib
import math
import base64
import time
from datetime import datetime, timedelta
from collections import Counter

# In-memory session state for serverless invocation
ALERT_HISTORY = [
    {
        "id": "ALT-1790320101-seed",
        "rule_id": "100001",
        "level": 12,
        "severity": "CRITICAL",
        "title": "SOC-LAB ALERT [CRITICAL]: Outbound connection to Known Malicious C2 Test IP",
        "mitre": "T1071.001",
        "time": "12:19:41",
        "status": "Active",
        "details": {
            "source_ip": "10.16.3.27",
            "destination_ip": "203.0.113.50",
            "destination_port": 443,
            "rule_name": "Outbound Connection to Malicious C2 Test IP",
            "process": "powershell.exe",
            "tactic": "Command & Control"
        }
    },
    {
        "id": "ALT-1790320255-seed",
        "rule_id": "100005",
        "level": 8,
        "severity": "MEDIUM",
        "title": "SOC-LAB ALERT [MEDIUM]: Obfuscated or Base64 Encoded PowerShell command detected",
        "mitre": "T1059.001",
        "time": "12:21:55",
        "status": "Active",
        "details": {
            "user": "SOC_Analyst",
            "command": "powershell.exe -EncodedCommand VGVzdFBheWxvYWQ=",
            "rule_name": "Obfuscated / Base64 Encoded PowerShell Command Execution",
            "tactic": "Defense Evasion"
        }
    }
]

QUARANTINE_VAULT = [
    "invoice_malware_sim.exe.quarantined_20260925_111149",
    "invoice_malware_sim.exe.quarantined_20260925_112951",
    "invoice_malware_sim.exe.quarantined_20260925_113832",
    "invoice_malware_sim.exe.quarantined_20260925_114204"
]

LAB_FILES = []

ACTIVITY_STREAM = [
    {
        "id": "EVT-1001",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": "SENTINEL_ONLINE",
        "severity": "INFO",
        "app": "CyberSOC Cloud Node",
        "title": "Vercel Edge Sentinel Online & Active",
        "details": {"message": "Continuous Cloud Monitoring Online"}
    },
    {
        "id": "EVT-1002",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": "USER_APP_FOCUS",
        "severity": "LOW",
        "app": "Google Chrome",
        "title": "CyberSOC Shield - Web Monitoring Platform",
        "details": {"window_title": "CyberSOC Shield - Web Monitoring Platform"}
    }
]

RULES = [
    {
        "id": "100001",
        "level": 12,
        "severity": "CRITICAL",
        "mitre": "T1071.001",
        "tactic": "Command & Control",
        "name": "Outbound Connection to Malicious C2 Test IP",
        "trigger": "Sysmon Event ID 3 (NetworkConnect)",
        "pattern": "203.0.113.50:443"
    },
    {
        "id": "100002",
        "level": 13,
        "severity": "CRITICAL",
        "mitre": "T1204.002",
        "tactic": "Execution",
        "name": "Execution of Process with Malicious IOC Hash",
        "trigger": "Sysmon Event ID 1 (ProcessCreate)",
        "pattern": "SHA256: 4a1b025fbc77660c6753a798a69eef52467d302a281898114f6d4d161d713c23"
    },
    {
        "id": "100003",
        "level": 10,
        "severity": "HIGH",
        "mitre": "T1105",
        "tactic": "Ingress Tool Transfer",
        "name": "Suspicious Dropper Executable Created on Disk",
        "trigger": "Sysmon Event ID 11 (FileCreate)",
        "pattern": "invoice_malware_sim.exe"
    },
    {
        "id": "100004",
        "level": 11,
        "severity": "HIGH",
        "mitre": "T1486",
        "tactic": "Impact (Ransomware)",
        "name": "Ransomware Extortion Note Dropped in Monitored Directory",
        "trigger": "Wazuh FIM / Syscheck (Rule 550 / 554)",
        "pattern": "test_ransom_note.txt"
    },
    {
        "id": "100005",
        "level": 8,
        "severity": "MEDIUM",
        "mitre": "T1059.001",
        "tactic": "Defense Evasion",
        "name": "Obfuscated / Base64 Encoded PowerShell Command Execution",
        "trigger": "Sysmon Event ID 1 / PowerShell Log",
        "pattern": "powershell.exe -EncodedCommand ..."
    },
    {
        "id": "100006",
        "level": 10,
        "severity": "HIGH",
        "mitre": "T1110",
        "tactic": "Credential Access",
        "name": "Potential Brute-Force Authentication Attack (3+ Fails / 60s)",
        "trigger": "Windows Security Event ID 4625",
        "pattern": "Account: lab_test_intruder"
    }
]

def analyze_file_content(filename: str, content: bytes):
    size_bytes = len(content)
    md5 = hashlib.md5(content).hexdigest()
    sha1 = hashlib.sha1(content).hexdigest()
    sha256 = hashlib.sha256(content).hexdigest()

    # Shannon Entropy
    if size_bytes > 0:
        counts = Counter(content)
        entropy = -sum((c / size_bytes) * math.log2(c / size_bytes) for c in counts.values())
        entropy = round(entropy, 2)
    else:
        entropy = 0.0

    # Extract printable ASCII strings (>= 4 chars)
    strings = []
    curr = []
    for b in content:
        if 32 <= b <= 126:
            curr.append(chr(b))
        else:
            if len(curr) >= 4:
                strings.append("".join(curr))
            curr = []
    if len(curr) >= 4:
        strings.append("".join(curr))

    matched_iocs = []
    suspicious_indicators = []
    threat_score = 0

    KNOWN_IOC_HASHES = {
        "4a1b025fbc77660c6753a798a69eef52467d302a281898114f6d4d161d713c23": "Pre-computed Malicious Test Dropper Hash (Rule 100002)"
    }
    if sha256 in KNOWN_IOC_HASHES:
        matched_iocs.append(f"Blacklisted Hash Match: {KNOWN_IOC_HASHES[sha256]}")
        threat_score += 85

    fn_lower = filename.lower()
    if "invoice_malware_sim" in fn_lower or "invoice" in fn_lower:
        matched_iocs.append("Known Trojan Dropper Filename Indicator (Rule 100003)")
        threat_score += 75

    if "test_ransom_note" in fn_lower or "ransom" in fn_lower:
        matched_iocs.append("Known Ransomware Note Pattern (Rule 100004)")
        threat_score += 70

    if fn_lower.endswith((".exe", ".dll", ".sys", ".scr", ".pif")):
        suspicious_indicators.append("Executable Windows Binary Architecture (PE32/PE64)")
        threat_score += 15

    if entropy > 7.2:
        suspicious_indicators.append(f"High Shannon Entropy ({entropy} / 8.0) - Encrypted, Obfuscated or Packed Code")
        threat_score += 35
    elif entropy > 6.4:
        suspicious_indicators.append(f"Elevated Shannon Entropy ({entropy} / 8.0) - Compressed or Encoded Structure")
        threat_score += 15

    joined_strings = " ".join(strings).lower()
    DANGEROUS_APIS = [
        ("virtualalloc", "Process Memory Allocation for Injection (VirtualAlloc)"),
        ("writeprocessmemory", "Process Injection Capability (WriteProcessMemory)"),
        ("createremotethread", "Remote Thread Injection (CreateRemoteThread)"),
        ("urldownloadtofile", "Payload Ingress Transfer (URLDownloadToFile)"),
        ("wscript.shell", "Execution Host (WScript.Shell)"),
        ("invoke-expression", "Dynamic Script Execution (Invoke-Expression / IEX)"),
        ("encodedcommand", "PowerShell Base64 Obfuscation (-EncodedCommand)"),
        ("vssadmin delete shadows", "Ransomware Shadow Copy Deletion (T1490)")
    ]
    for api_token, desc in DANGEROUS_APIS:
        if api_token in joined_strings:
            suspicious_indicators.append(desc)
            threat_score += 20

    if "203.0.113.50" in joined_strings:
        matched_iocs.append("Embedded Malicious C2 IP Indicator: 203.0.113.50:443")
        threat_score += 50

    ransom_keywords = ["ransom", "bitcoin", "decrypt", "encrypted", "private key", "all your files"]
    found_ransom = [k for k in ransom_keywords if k in joined_strings]
    if len(found_ransom) >= 2:
        suspicious_indicators.append(f"Ransomware Extortion Phrases: {', '.join(found_ransom)}")
        threat_score += 40

    threat_score = min(threat_score, 100)
    if threat_score >= 60:
        verdict = "MALICIOUS"
        severity = "CRITICAL"
    elif threat_score >= 25:
        verdict = "SUSPICIOUS"
        severity = "HIGH"
    else:
        verdict = "CLEAN / BENIGN"
        severity = "LOW"

    return {
        "filename": filename,
        "size_bytes": size_bytes,
        "size_human": f"{size_bytes / 1024:.1f} KB" if size_bytes < 1048576 else f"{size_bytes / (1024*1024):.2f} MB",
        "hashes": {"md5": md5, "sha1": sha1, "sha256": sha256},
        "entropy": entropy,
        "threat_score": threat_score,
        "verdict": verdict,
        "severity": severity,
        "matched_iocs": matched_iocs,
        "suspicious_indicators": suspicious_indicators,
        "indicators": [{"name": "Known Threat IOC", "desc": x} for x in matched_iocs] + [{"name": "Heuristic Indicator", "desc": x} for x in suspicious_indicators],
        "sample_strings": strings[:50],
        "extracted_strings_sample": strings[:50],
        "analysis_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

class handler(BaseHTTPRequestHandler):
    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/")
        if not path.startswith("/api"):
            path = "/api" + path

        if path in ["/api/status", "/api"]:
            self._send_json({
                "hostname": "CyberSOC-Cloud-Node",
                "ip": "10.16.3.27 (Vercel Edge)",
                "os": "CyberSOC Shield Cloud Sentinel (Linux/Vercel)",
                "firewall_containment": "CONTAINMENT ACTIVE (C2 203.0.113.50 Blocked)",
                "lab_files": LAB_FILES,
                "quarantine_files": QUARANTINE_VAULT,
                "total_alerts": len(ALERT_HISTORY),
                "sensors": {
                    "sysmon": "ACTIVE",
                    "wazuh_agent": "READY",
                    "fim_watcher": "MONITORING",
                    "containment_fw": "ACTIVE"
                }
            })
            return

        elif path == "/api/telemetry":
            now_str = datetime.now().strftime("%H:%M:%S")
            self._send_json({
                "timestamp": now_str,
                "memory": {
                    "total_mb": 8192,
                    "used_mb": 6240,
                    "free_mb": 1952,
                    "percent": 76
                },
                "processes": [
                    {"Name": "Antigravity IDE", "Id": 17292, "MemMB": 598.6},
                    {"Name": "wazuh-agent.exe", "Id": 4820, "MemMB": 312.4},
                    {"Name": "sysmon-collector.exe", "Id": 3210, "MemMB": 286.0},
                    {"Name": "soc-telemetry-engine", "Id": 8940, "MemMB": 204.8},
                    {"Name": "kernel-guard.exe", "Id": 11204, "MemMB": 185.3}
                ]
            })
            return

        elif path == "/api/activity-stream":
            self._send_json({
                "uptime": {
                    "uptime_seconds": 14250,
                    "uptime_human": "3h 57m 30s",
                    "hours": 3,
                    "minutes": 57,
                    "seconds": 30,
                    "boot_time": "2026-09-25 10:45:00",
                    "boot_timestamp": "2026-09-25 10:45:00"
                },
                "current_app": "Antigravity IDE",
                "active_app": "Antigravity IDE",
                "current_window": "Cyber project - CyberSOC Shield Dashboard",
                "active_window": "Cyber project - CyberSOC Shield Dashboard",
                "total_events": len(ACTIVITY_STREAM),
                "activities": ACTIVITY_STREAM,
                "stream": ACTIVITY_STREAM
            })
            return

        elif path == "/api/network-traffic":
            conns = [
                {"proto": "TCP", "local": "10.16.3.27:5050", "remote": "0.0.0.0:0", "state": "LISTENING", "pid": "5050", "process": "python.exe (CyberSOC Server)", "is_threat": False},
                {"proto": "TCP", "local": "10.16.3.27:49408", "remote": "4.145.79.80:443", "state": "ESTABLISHED", "pid": "17292", "process": "Antigravity IDE", "is_threat": False},
                {"proto": "TCP", "local": "10.16.3.27:50494", "remote": "203.0.113.50:443", "state": "BLOCKED", "pid": "16132", "process": "powershell.exe", "is_threat": True},
                {"proto": "TCP", "local": "10.16.3.27:51200", "remote": "142.250.190.46:443", "state": "ESTABLISHED", "pid": "17480", "process": "chrome.exe", "is_threat": False},
                {"proto": "TCP", "local": "10.16.3.27:1514", "remote": "192.168.1.100:1514", "state": "ESTABLISHED", "pid": "4820", "process": "wazuh-agent.exe", "is_threat": False}
            ]
            self._send_json(conns)
            return

        elif path == "/api/alerts":
            self._send_json(ALERT_HISTORY)
            return

        elif path == "/api/rules":
            self._send_json(RULES)
            return

        elif path == "/api/export-report":
            report = {
                "report_title": "CyberSOC Shield Incident Investigation Dossier",
                "classification": "CONFIDENTIAL // DEFENSIVE SOC AUDIT",
                "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "total_alerts": len(ALERT_HISTORY),
                "quarantine_items": QUARANTINE_VAULT,
                "alerts": ALERT_HISTORY
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Disposition", "attachment; filename=soc_incident_report.json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(report, indent=2).encode("utf-8"))
            return

        elif path == "/api/export-activity-log":
            lines = [json.dumps(e) for e in ACTIVITY_STREAM]
            content = "\n".join(lines).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/jsonlines")
            self.send_header("Content-Disposition", "attachment; filename=system_activity_audit.jsonl")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(content)
            return

        self._send_json({"error": "Endpoint not found"}, status=404)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/")
        if not path.startswith("/api"):
            path = "/api" + path

        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
        try:
            payload = json.loads(post_data)
        except Exception:
            payload = {}

        if path == "/api/analyze-malware":
            filename = payload.get("filename", "uploaded_sample.bin")
            content_b64 = payload.get("content_b64") or payload.get("content_base64", "")
            try:
                raw_bytes = base64.b64decode(content_b64)
            except Exception:
                raw_bytes = b""

            report = analyze_file_content(filename, raw_bytes)

            if report["verdict"] in ["MALICIOUS", "SUSPICIOUS"]:
                alert = {
                    "id": f"ALT-{int(time.time())}-malware",
                    "rule_id": "100003" if "Dropper" in str(report["matched_iocs"]) else "100002",
                    "level": 13 if report["verdict"] == "MALICIOUS" else 10,
                    "severity": report["severity"],
                    "title": f"MALWARE ANALYZER ALERT: {report['verdict']} sample analyzed [{filename}]",
                    "mitre": "T1204.002",
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "status": "Active",
                    "details": {
                        "filename": filename,
                        "sha256": report["hashes"]["sha256"],
                        "threatScore": f"{report['threat_score']}/100",
                        "entropy": report["entropy"],
                        "indicators": [ind["desc"] for ind in report.get("indicators", [])]
                    }
                }
                ALERT_HISTORY.insert(0, alert)

            self._send_json(report)
            return

        elif path == "/api/quarantine-sample":
            filename = payload.get("filename", "threat_sample.bin")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            quarantined_name = f"{filename}.quarantined_{timestamp}"
            QUARANTINE_VAULT.insert(0, quarantined_name)

            self._send_json({
                "success": True,
                "message": f"Sample neutralized and quarantined to Vault: {quarantined_name}",
                "path": quarantined_name,
                "vault_path": quarantined_name
            })
            return

        elif path == "/api/simulate":
            test_type = payload.get("test", "all")
            now_time = datetime.now().strftime("%H:%M:%S")

            new_alerts = [
                {
                    "id": f"ALT-{int(time.time())}-sim1",
                    "rule_id": "100001",
                    "level": 12,
                    "severity": "CRITICAL",
                    "title": "SOC-LAB ALERT [CRITICAL]: Outbound connection to Known Malicious C2 Test IP",
                    "mitre": "T1071.001",
                    "time": now_time,
                    "status": "Active",
                    "details": {"destination": "203.0.113.50:443", "protocol": "TCP", "sensor": "Sysmon Event ID 3"}
                },
                {
                    "id": f"ALT-{int(time.time())}-sim3",
                    "rule_id": "100003",
                    "level": 10,
                    "severity": "HIGH",
                    "title": "SOC-LAB ALERT [HIGH]: Suspicious Dropper Executable Created on Disk",
                    "mitre": "T1105",
                    "time": now_time,
                    "status": "Active",
                    "details": {"file": "invoice_malware_sim.exe", "path": "C:\\SOC_Lab_Test", "sensor": "Sysmon Event ID 11"}
                }
            ]

            for a in new_alerts:
                ALERT_HISTORY.insert(0, a)

            self._send_json({
                "output": f"[+] Threat Simulation [{test_type}] executed successfully in Cloud Lab environment.\n[+] Generated simulated Sysmon and Wazuh network beacon events.",
                "alerts_generated": len(new_alerts)
            })
            return

        elif path == "/api/simulate-auth":
            now_time = datetime.now().strftime("%H:%M:%S")
            auth_alert = {
                "id": f"ALT-{int(time.time())}-auth",
                "rule_id": "100006",
                "level": 10,
                "severity": "HIGH",
                "title": "SOC-LAB ALERT [HIGH]: Potential Brute-Force Authentication Attack (4 fails in 60s)",
                "mitre": "T1110",
                "time": now_time,
                "status": "Active",
                "details": {"target_account": "lab_test_intruder", "failed_attempts": 4, "event_id": 4625}
            }
            ALERT_HISTORY.insert(0, auth_alert)

            self._send_json({
                "output": "[+] Auth Simulation completed: 4 failed logons generated for user 'lab_test_intruder'.\n[+] Triggered Rule 100006 (Event ID 4625 brute-force detection).",
                "alerts_generated": 1
            })
            return

        elif path == "/api/containment":
            for a in ALERT_HISTORY:
                a["status"] = "Mitigated (Contained)"
            self._send_json({
                "status": "CONTAINED",
                "actions": [
                    "Host Isolation Rule activated: Blocked outbound socket to 203.0.113.50:443",
                    "Quarantine Vault locked: All test threat artifacts moved to safe storage",
                    "Active alerts marked as Mitigated"
                ]
            })
            return

        elif path == "/api/clear":
            ALERT_HISTORY.clear()
            self._send_json({"status": "cleared"})
            return

        self._send_json({"error": "Endpoint not found"}, status=404)
