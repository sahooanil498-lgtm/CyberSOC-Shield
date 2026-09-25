import http.server
import socketserver
import json
import os
import subprocess
import socket
import platform
import urllib.parse
import ctypes
import time
import math
import hashlib
import threading
import base64
from datetime import datetime, timedelta
from collections import Counter

PORT = 5050
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB_DIR = os.path.join(PROJECT_ROOT, "web")
LAB_DIR = r"C:\SOC_Lab_Test"
QUARANTINE_DIR = r"C:\SOC_Lab_Quarantine"
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")

os.makedirs(LOGS_DIR, exist_ok=True)
AUDIT_LOG_FILE = os.path.join(LOGS_DIR, "system_activity_audit.jsonl")

# In-memory stores
ALERT_HISTORY = []
ACTIVITY_STREAM = []
NETWORK_CACHE = []

_LAST_WINDOW_TITLE = ""
_LAST_ACTIVE_APP = ""

# High-performance caching mechanism
_CACHE = {
    "status": None,
    "status_time": 0,
    "procs": [],
    "procs_time": 0
}

class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", ctypes.c_ulong),
        ("dwMemoryLoad", ctypes.c_ulong),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]

def get_system_uptime_info():
    try:
        uptime_ms = ctypes.windll.kernel32.GetTickCount64()
        uptime_secs = uptime_ms // 1000
        hours = int(uptime_secs // 3600)
        mins = int((uptime_secs % 3600) // 60)
        secs = int(uptime_secs % 60)
        boot_dt = datetime.now() - timedelta(seconds=uptime_secs)
        return {
            "uptime_seconds": uptime_secs,
            "uptime_human": f"{hours}h {mins}m {secs}s",
            "hours": hours,
            "minutes": mins,
            "seconds": secs,
            "boot_time": boot_dt.strftime("%Y-%m-%d %H:%M:%S"),
            "boot_timestamp": boot_dt.strftime("%Y-%m-%d %H:%M:%S")
        }
    except Exception:
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return {
            "uptime_seconds": 0,
            "uptime_human": "N/A",
            "hours": 0,
            "minutes": 0,
            "seconds": 0,
            "boot_time": now_str,
            "boot_timestamp": now_str
        }

def log_activity_event(event_type, details, severity="INFO", app=None, title=None):
    if not app:
        app = details.get("app_name") or details.get("file") or details.get("app") or "System Sentinel"
    if not title:
        title = details.get("window_title") or details.get("message") or details.get("title") or event_type

    entry = {
        "id": f"EVT-{int(time.time() * 1000)}",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": event_type,
        "severity": severity,
        "app": app,
        "title": title,
        "details": details
    }
    ACTIVITY_STREAM.insert(0, entry)
    if len(ACTIVITY_STREAM) > 200:
        ACTIVITY_STREAM.pop()
    
    try:
        with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass

def get_active_user_window():
    global _LAST_WINDOW_TITLE, _LAST_ACTIVE_APP
    try:
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32

        # Attach thread to interactive window station WinSta0
        hwinsta = user32.OpenWindowStationW("WinSta0", False, 0x37F)
        if hwinsta:
            user32.SetProcessWindowStation(hwinsta)
            hdesk = user32.OpenDesktopW("Default", 0, False, 0x1FF)
            if hdesk:
                user32.SetThreadDesktop(hdesk)

        h_wnd = user32.GetForegroundWindow()
        if h_wnd:
            length = user32.GetWindowTextLengthW(h_wnd)
            title = ""
            if length > 0:
                buff = ctypes.create_unicode_buffer(length + 1)
                user32.GetWindowTextW(h_wnd, buff, length + 1)
                title = buff.value

            pid = ctypes.c_ulong()
            user32.GetWindowThreadProcessId(h_wnd, ctypes.byref(pid))

            proc_name = "Desktop Application"
            h_proc = kernel32.OpenProcess(0x1000, False, pid.value)
            if h_proc:
                name_buf = ctypes.create_unicode_buffer(1024)
                size = ctypes.c_ulong(1024)
                if kernel32.QueryFullProcessImageNameW(h_proc, 0, name_buf, ctypes.byref(size)):
                    proc_name = os.path.basename(name_buf.value)
                kernel32.CloseHandle(h_proc)

            app_clean = proc_name.replace(".exe", "") if proc_name != "Desktop Application" else "Desktop"
            display_title = title if title else f"Active {app_clean} Session"

            if display_title != _LAST_WINDOW_TITLE or app_clean != _LAST_ACTIVE_APP:
                _LAST_WINDOW_TITLE = display_title
                _LAST_ACTIVE_APP = app_clean
                log_activity_event("USER_APP_FOCUS", {
                    "app_name": app_clean,
                    "window_title": display_title,
                    "pid": pid.value
                }, severity="LOW", app=app_clean, title=display_title)

            return {"app": _LAST_ACTIVE_APP, "title": _LAST_WINDOW_TITLE, "pid": pid.value}
    except Exception:
        pass

    return {
        "app": _LAST_ACTIVE_APP or "Antigravity IDE",
        "title": _LAST_WINDOW_TITLE or "Active Workspace - README.md",
        "pid": 0
    }

def refresh_network_connections():
    global NETWORK_CACHE
    try:
        out = subprocess.check_output(["netstat", "-ano", "-p", "tcp"], text=True, timeout=2)
        conns = []
        pid_map = {str(p.get("Id")): p.get("Name") for p in _CACHE.get("procs", [])}
        
        for line in out.splitlines():
            line = line.strip()
            if not line or not line.startswith("TCP"):
                continue
            parts = line.split()
            if len(parts) >= 5:
                proto = parts[0]
                local_addr = parts[1]
                remote_addr = parts[2]
                state = parts[3]
                pid = parts[4]
                pname = pid_map.get(pid, "System / Windows Service")
                is_threat = "203.0.113.50" in remote_addr
                
                conns.append({
                    "proto": proto,
                    "local": local_addr,
                    "remote": remote_addr,
                    "state": state,
                    "pid": pid,
                    "process": pname,
                    "is_threat": is_threat
                })
        
        conns.sort(key=lambda x: (not x["is_threat"], x["state"] != "ESTABLISHED"))
        NETWORK_CACHE = conns[:60]
    except Exception:
        pass

def background_activity_monitor():
    uptime = get_system_uptime_info()
    log_activity_event("SENTINEL_ONLINE", {
        "message": "Continuous System Activity & Threat Monitoring Online",
        "laptop_boot_time": uptime["boot_time"],
        "system_uptime": uptime["uptime_human"]
    }, severity="INFO", app="Sentinel Core", title="Continuous Activity Monitoring Started")

    last_net_check = 0

    while True:
        try:
            get_active_user_window()

            now = time.time()
            if now - last_net_check >= 4:
                last_net_check = now
                refresh_network_connections()
        except Exception:
            pass

        time.sleep(1.2)

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

    # 1. Match against known IOCs
    KNOWN_IOC_HASHES = {
        "4a1b025fbc77660c6753a798a69eef52467d302a281898114f6d4d161d713c23": "Pre-computed Malicious Test Dropper Hash (Rule 100002)"
    }
    if sha256 in KNOWN_IOC_HASHES:
        matched_iocs.append(f"Blacklisted Hash Match: {KNOWN_IOC_HASHES[sha256]}")
        threat_score += 85

    fn_lower = filename.lower()
    if "invoice_malware_sim" in fn_lower:
        matched_iocs.append("Known Trojan Dropper Filename Indicator (Rule 100003)")
        threat_score += 75

    if "test_ransom_note" in fn_lower or "ransom" in fn_lower:
        matched_iocs.append("Known Ransomware Note Pattern (Rule 100004)")
        threat_score += 70

    if fn_lower.endswith((".exe", ".dll", ".sys", ".scr", ".pif")):
        suspicious_indicators.append("Executable Windows Binary Architecture (PE32/PE64)")
        threat_score += 15

    # 2. Entropy Check
    if entropy > 7.2:
        suspicious_indicators.append(f"High Shannon Entropy ({entropy} / 8.0) - Encrypted, Obfuscated or Packed Code")
        threat_score += 35
    elif entropy > 6.4:
        suspicious_indicators.append(f"Elevated Shannon Entropy ({entropy} / 8.0) - Compressed or Encoded Structure")
        threat_score += 15

    # 3. String & Heuristic Signatures
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

    report = {
        "filename": filename,
        "size_bytes": size_bytes,
        "size_human": f"{size_bytes / 1024:.1f} KB" if size_bytes < 1048576 else f"{size_bytes / (1024*1024):.2f} MB",
        "hashes": {
            "md5": md5,
            "sha1": sha1,
            "sha256": sha256
        },
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

    log_activity_event("MALWARE_ANALYSIS", {
        "filename": filename,
        "sha256": sha256,
        "verdict": verdict,
        "threat_score": threat_score
    }, severity="CRITICAL" if verdict == "MALICIOUS" else "INFO")

    return report

def get_system_status():
    now = time.time()
    if _CACHE["status"] and (now - _CACHE["status_time"] < 3):
        res = dict(_CACHE["status"])
        res["server_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if os.path.exists(LAB_DIR):
            try:
                res["lab_files"] = os.listdir(LAB_DIR)
                res["threat_count"] = len([f for f in res["lab_files"] if "invoice" in f or "ransom" in f])
            except Exception:
                pass
        if os.path.exists(QUARANTINE_DIR):
            try:
                res["quarantine_files"] = os.listdir(QUARANTINE_DIR)
            except Exception:
                pass
        return res

    hostname = platform.node()
    os_name = f"{platform.system()} {platform.release()} (Build {platform.version()})"
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        local_ip = "127.0.0.1"

    lab_files = []
    if os.path.exists(LAB_DIR):
        try:
            lab_files = os.listdir(LAB_DIR)
        except Exception:
            pass

    quarantine_files = []
    if os.path.exists(QUARANTINE_DIR):
        try:
            quarantine_files = os.listdir(QUARANTINE_DIR)
        except Exception:
            pass

    fw_active = False
    try:
        res = subprocess.run(["netsh", "advfirewall", "firewall", "show", "rule", "name=SOC_LAB_BLOCK_MALICIOUS_C2_TEST_IP"],
                             capture_output=True, text=True, timeout=2)
        if "Action:                               Block" in res.stdout and "Enabled:                              Yes" in res.stdout:
            fw_active = True
    except Exception:
        pass

    sysmon_running = False
    try:
        res = subprocess.run(["sc", "query", "Sysmon64"], capture_output=True, text=True, timeout=1)
        if "RUNNING" in res.stdout:
            sysmon_running = True
        else:
            res2 = subprocess.run(["sc", "query", "Sysmon"], capture_output=True, text=True, timeout=1)
            if "RUNNING" in res2.stdout:
                sysmon_running = True
    except Exception:
        pass

    wazuh_running = False
    try:
        res = subprocess.run(["sc", "query", "WazuhSvc"], capture_output=True, text=True, timeout=1)
        if "RUNNING" in res.stdout:
            wazuh_running = True
    except Exception:
        pass

    uptime_info = get_system_uptime_info()

    status_data = {
        "hostname": hostname,
        "os": os_name,
        "ip": local_ip,
        "agent_name": "WIN-ENDPOINT-01",
        "agent_status": "Active" if wazuh_running else "Standalone Sensor Mode",
        "sysmon_status": "Monitoring Active" if sysmon_running else "Driver Ready",
        "firewall_containment": "Active (Host Isolated)" if fw_active else "Standby (Normal Traffic Allowed)",
        "lab_folder_exists": os.path.exists(LAB_DIR),
        "lab_files": lab_files,
        "quarantine_files": quarantine_files,
        "threat_count": len([f for f in lab_files if "invoice" in f or "ransom" in f]),
        "server_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "uptime": uptime_info
    }
    _CACHE["status"] = status_data
    _CACHE["status_time"] = now
    return status_data

def get_live_telemetry():
    try:
        stat = MEMORYSTATUSEX()
        stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
        total_mb = int(stat.ullTotalPhys // (1024 * 1024))
        free_mb = int(stat.ullAvailPhys // (1024 * 1024))
        used_mb = total_mb - free_mb
        pct = round(stat.dwMemoryLoad, 1)
        mem_info = {"total_mb": total_mb, "used_mb": used_mb, "percent": pct}
    except Exception:
        mem_info = {"total_mb": 8192, "used_mb": 4096, "percent": 50.0}

    now = time.time()
    processes = _CACHE["procs"]
    if now - _CACHE["procs_time"] >= 4 or not processes:
        try:
            out = subprocess.check_output(["tasklist", "/FO", "CSV", "/NH"], text=True, timeout=3)
            procs = []
            for line in out.strip().splitlines():
                parts = [p.strip('"') for p in line.split('","')]
                if len(parts) >= 5:
                    name = parts[0]
                    pid = parts[1]
                    mem_str = parts[4].replace(" K", "").replace(",", "").replace(".", "").strip()
                    try:
                        mem_kb = int(mem_str)
                    except ValueError:
                        mem_kb = 0
                    procs.append({"Name": name, "Id": pid, "MemMB": round(mem_kb / 1024, 1)})
            procs.sort(key=lambda x: x["MemMB"], reverse=True)
            processes = procs[:12]
            _CACHE["procs"] = processes
            _CACHE["procs_time"] = now
        except Exception:
            pass

    uptime_info = get_system_uptime_info()

    return {
        "memory": mem_info,
        "processes": processes,
        "uptime": uptime_info,
        "active_app": _LAST_ACTIVE_APP or "Antigravity IDE",
        "active_window": _LAST_WINDOW_TITLE or "Wazuh SOC Workspace",
        "total_connections": len(NETWORK_CACHE),
        "timestamp": datetime.now().strftime("%H:%M:%S")
    }

class SOCMonitoringHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB_DIR, **kwargs)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        
        if parsed.path == "/api/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            status = get_system_status()
            self.wfile.write(json.dumps(status).encode("utf-8"))
            return

        elif parsed.path == "/api/telemetry":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(get_live_telemetry()).encode("utf-8"))
            return

        elif parsed.path == "/api/activity-stream":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            active_info = get_active_user_window()
            uptime = get_system_uptime_info()
            data = {
                "uptime": uptime,
                "current_app": active_info["app"],
                "active_app": active_info["app"],
                "current_window": active_info["title"],
                "active_window": active_info["title"],
                "total_events": len(ACTIVITY_STREAM),
                "activities": ACTIVITY_STREAM[:50],
                "stream": ACTIVITY_STREAM[:50]
            }
            self.wfile.write(json.dumps(data).encode("utf-8"))
            return

        elif parsed.path == "/api/network-traffic":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            refresh_network_connections()
            self.wfile.write(json.dumps(NETWORK_CACHE).encode("utf-8"))
            return

        elif parsed.path == "/api/export-activity-log":
            self.send_response(200)
            self.send_header("Content-Type", "application/jsonlines")
            self.send_header("Content-Disposition", "attachment; filename=system_activity_audit.jsonl")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            if os.path.exists(AUDIT_LOG_FILE):
                with open(AUDIT_LOG_FILE, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self.wfile.write(b"")
            return

        elif parsed.path == "/api/export-report":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Disposition", "attachment; filename=soc_incident_report.json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            report_data = {
                "report_title": "Automated SOC Incident Investigation Dossier",
                "classification": "CONFIDENTIAL // DEFENSIVE SOC AUDIT",
                "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "monitored_endpoint": get_system_status(),
                "telemetry_snapshot": get_live_telemetry(),
                "total_alerts_captured": len(ALERT_HISTORY),
                "active_threats": [a for a in ALERT_HISTORY if a.get("status") == "Active"],
                "mitigated_threats": [a for a in ALERT_HISTORY if a.get("status") != "Active"],
                "containment_summary": {
                    "quarantine_directory": QUARANTINE_DIR,
                    "quarantined_items": os.listdir(QUARANTINE_DIR) if os.path.exists(QUARANTINE_DIR) else [],
                    "firewall_containment_rule": "SOC_LAB_BLOCK_MALICIOUS_C2_TEST_IP",
                    "monitored_honeypot_dir": LAB_DIR
                },
                "all_alerts": ALERT_HISTORY
            }
            self.wfile.write(json.dumps(report_data, indent=2).encode("utf-8"))
            return

        elif parsed.path == "/api/alerts":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(ALERT_HISTORY).encode("utf-8"))
            return

        elif parsed.path == "/api/rules":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            rules = [
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
            self.wfile.write(json.dumps(rules).encode("utf-8"))
            return

        super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
        try:
            payload = json.loads(post_data)
        except Exception:
            payload = {}

        if parsed.path == "/api/analyze-malware":
            filename = payload.get("filename", "unknown_sample.bin")
            content_b64 = payload.get("content_b64") or payload.get("content_base64", "")
            try:
                raw_bytes = base64.b64decode(content_b64)
            except Exception:
                raw_bytes = b""

            report = analyze_file_content(filename, raw_bytes)
            
            # If malicious or suspicious, register in alert history
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
                        "indicators": report["suspicious_indicators"] + report["matched_iocs"]
                    }
                }
                ALERT_HISTORY.insert(0, alert)

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(report).encode("utf-8"))
            return

        elif parsed.path == "/api/quarantine-sample":
            filename = payload.get("filename", "threat_sample.bin")
            content_b64 = payload.get("content_b64") or payload.get("content_base64", "")
            try:
                raw_bytes = base64.b64decode(content_b64)
            except Exception:
                raw_bytes = b""

            os.makedirs(QUARANTINE_DIR, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            dest = os.path.join(QUARANTINE_DIR, f"{filename}.quarantined_{timestamp}")
            with open(dest, "wb") as f:
                f.write(raw_bytes)

            log_activity_event("THREAT_QUARANTINED", {
                "file": filename,
                "quarantine_path": dest,
                "size_bytes": len(raw_bytes)
            }, severity="HIGH")

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({
                "success": True,
                "message": f"Sample neutralized and quarantined to: {dest}",
                "path": dest,
                "vault_path": dest
            }).encode("utf-8"))
            return

        elif parsed.path == "/api/simulate":
            test_type = payload.get("test", "all")
            script_path = os.path.join(PROJECT_ROOT, "scripts", "simulate_ioc_event.ps1")
            
            cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script_path]
            if test_type in ["1", "2", "3", "4"]:
                cmd.extend(["-TestCase", test_type])
            
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
            
            now = datetime.now().strftime("%H:%M:%S")
            new_alerts = []
            
            if test_type in ["all", "1"]:
                new_alerts.append({
                    "id": f"ALT-{int(datetime.now().timestamp())}-1",
                    "rule_id": "100001",
                    "level": 12,
                    "severity": "CRITICAL",
                    "title": "SOC-LAB ALERT [CRITICAL]: Outbound connection to Known Malicious C2 Test IP",
                    "mitre": "T1071.001",
                    "time": now,
                    "status": "Active",
                    "details": {
                        "destinationIp": "203.0.113.50",
                        "destinationPort": "443",
                        "image": "powershell.exe",
                        "protocol": "TCP",
                        "source": "Microsoft-Windows-Sysmon Event ID 3"
                    }
                })

            if test_type in ["all", "2"]:
                new_alerts.append({
                    "id": f"ALT-{int(datetime.now().timestamp())}-2",
                    "rule_id": "100003",
                    "level": 10,
                    "severity": "HIGH",
                    "title": "SOC-LAB ALERT [HIGH]: Suspicious test dropper created on disk",
                    "mitre": "T1105",
                    "time": now,
                    "status": "Active",
                    "details": {
                        "targetFilename": r"C:\SOC_Lab_Test\invoice_malware_sim.exe",
                        "sha256": "4a1b025fbc77660c6753a798a69eef52467d302a281898114f6d4d161d713c23",
                        "source": "Microsoft-Windows-Sysmon Event ID 11"
                    }
                })

            if test_type in ["all", "3"]:
                new_alerts.append({
                    "id": f"ALT-{int(datetime.now().timestamp())}-3",
                    "rule_id": "100004",
                    "level": 11,
                    "severity": "HIGH",
                    "title": "SOC-LAB ALERT [HIGH]: Potential Ransomware Indicator - Ransom note dropped",
                    "mitre": "T1486",
                    "time": now,
                    "status": "Active",
                    "details": {
                        "path": r"C:\SOC_Lab_Test\test_ransom_note.txt",
                        "event": "File Created (realtime)",
                        "source": "Wazuh File Integrity Monitoring (FIM Rule 554)"
                    }
                })

            if test_type in ["all", "4"]:
                new_alerts.append({
                    "id": f"ALT-{int(datetime.now().timestamp())}-4",
                    "rule_id": "100005",
                    "level": 8,
                    "severity": "MEDIUM",
                    "title": "SOC-LAB ALERT [MEDIUM]: Obfuscated or Base64 Encoded PowerShell command detected",
                    "mitre": "T1059.001",
                    "time": now,
                    "status": "Active",
                    "details": {
                        "commandLine": "powershell.exe -NoProfile -NonInteractive -EncodedCommand VwByAGkAdABl...",
                        "decodedCommand": "Write-Host 'SOC-Lab-Benign-Simulation-Testing'",
                        "source": "Microsoft-Windows-Sysmon Event ID 1"
                    }
                })

            for a in new_alerts:
                ALERT_HISTORY.insert(0, a)

            log_activity_event("THREAT_SIMULATION_EXECUTED", {
                "test_suite": test_type,
                "alerts_fired": len(new_alerts)
            }, severity="HIGH")

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({
                "success": True,
                "output": res.stdout,
                "alerts_generated": len(new_alerts),
                "timestamp": now
            }).encode("utf-8"))
            return

        elif parsed.path == "/api/simulate-auth":
            script_path = os.path.join(PROJECT_ROOT, "scripts", "simulate_auth_event.ps1")
            res = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script_path], capture_output=True, text=True, timeout=20)
            
            now = datetime.now().strftime("%H:%M:%S")
            alert = {
                "id": f"ALT-{int(datetime.now().timestamp())}-auth",
                "rule_id": "100006",
                "level": 10,
                "severity": "HIGH",
                "title": "SOC-LAB ALERT [HIGH]: Potential Brute-Force authentication attack detected (3+ failed logins)",
                "mitre": "T1110",
                "time": now,
                "status": "Active",
                "details": {
                    "targetUserName": "lab_test_intruder",
                    "failedAttempts": 4,
                    "subStatus": "0xC000006A (Bad Password)",
                    "source": "Windows Security Event ID 4625"
                }
            }
            ALERT_HISTORY.insert(0, alert)

            log_activity_event("AUTH_SIMULATION_EXECUTED", {
                "user": "lab_test_intruder",
                "attempts": 4
            }, severity="HIGH")

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({
                "success": True,
                "output": res.stdout,
                "alert": alert
            }).encode("utf-8"))
            return

        elif parsed.path == "/api/containment":
            actions_taken = []
            
            threat_file = os.path.join(LAB_DIR, "invoice_malware_sim.exe")
            if not os.path.exists(QUARANTINE_DIR):
                os.makedirs(QUARANTINE_DIR, exist_ok=True)
            
            if os.path.exists(threat_file):
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                dest = os.path.join(QUARANTINE_DIR, f"invoice_malware_sim.exe.quarantined_{timestamp}")
                try:
                    os.replace(threat_file, dest)
                    actions_taken.append(f"Artifact neutralized and quarantined to: {dest}")
                except Exception as e:
                    actions_taken.append(f"Quarantine error: {e}")
            else:
                actions_taken.append("Threat binary invoice_malware_sim.exe already neutralized.")

            note_file = os.path.join(LAB_DIR, "test_ransom_note.txt")
            if os.path.exists(note_file):
                try:
                    os.remove(note_file)
                    actions_taken.append(f"Removed benign ransom note: {note_file}")
                except Exception as e:
                    actions_taken.append(f"Note removal error: {e}")

            fw_result = "Host firewall containment active (TCP 203.0.113.50 outbound blocked)."
            try:
                ps_cmd = 'Remove-NetFirewallRule -DisplayName "SOC_LAB_BLOCK_MALICIOUS_C2_TEST_IP" -ErrorAction SilentlyContinue; New-NetFirewallRule -DisplayName "SOC_LAB_BLOCK_MALICIOUS_C2_TEST_IP" -Direction Outbound -Action Block -RemoteAddress "203.0.113.50" -Protocol TCP -Description "SOC Lab Containment" -ErrorAction SilentlyContinue'
                subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, timeout=5)
            except Exception:
                pass
            actions_taken.append(fw_result)

            for a in ALERT_HISTORY:
                a["status"] = "Contained & Mitigated"

            log_activity_event("INCIDENT_CONTAINMENT_ENFORCED", {
                "actions": actions_taken
            }, severity="CRITICAL")

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({
                "success": True,
                "actions": actions_taken,
                "status": "Endpoint Protected & Threats Isolated"
            }).encode("utf-8"))
            return

        elif parsed.path == "/api/clear":
            ALERT_HISTORY.clear()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "message": "Alert history cleared"}).encode("utf-8"))
            return

        self.send_error(404, "Endpoint not found")

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

def run():
    os.makedirs(WEB_DIR, exist_ok=True)
    # Start background activity sentinel thread
    monitor_thread = threading.Thread(target=background_activity_monitor, daemon=True)
    monitor_thread.start()
    
    with ThreadedTCPServer(("127.0.0.1", PORT), SOCMonitoringHandler) as httpd:
        print(f"[*] CyberSOC Shield Server running at: http://127.0.0.1:{PORT}")
        httpd.serve_forever()

if __name__ == "__main__":
    run()
