#!/usr/bin/env python3
"""
SIEM Universal Endpoint Agent (Linux & Windows)
Permanent, boot-persistent agent with local buffering, auto-reconnect,
dynamic network change detection, and resilient background execution.
"""

from __future__ import annotations
import sys
import os
import time
import socket
import platform
import uuid
import json
import logging
import subprocess
import re
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
import urllib.request
import urllib.error

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] [SIEM-Agent] %(message)s'
)
logger = logging.getLogger("SIEMAgent")

# Determine persistent config locations
def get_config_path() -> str:
    if platform.system() == "Windows":
        prog_data = os.environ.get("ProgramData", "C:\\ProgramData")
        target_dir = os.path.join(prog_data, "SIEMAgent")
    else:
        # Linux / Unix
        if os.geteuid() == 0:
            target_dir = "/etc/siem-agent"
        else:
            target_dir = os.path.expanduser("~/.config/siem-agent")
    
    os.makedirs(target_dir, exist_ok=True)
    return os.path.join(target_dir, "agent_config.json")

class AgentConfig:
    def __init__(self):
        self.file_path = get_config_path()
        self.server_url = "http://127.0.0.1:8000"
        self.enrollment_token = ""
        self.device_id = None
        self.device_credential = None
        self.heartbeat_interval = 15
        self.metric_interval = 10
        self.log_interval = 10
        self.load()

    def load(self):
        # Also check local file as fallback
        candidates = [self.file_path, "agent_config.json"]
        for p in candidates:
            if os.path.exists(p):
                try:
                    with open(p, "r") as f:
                        data = json.load(f)
                        self.server_url = data.get("server_url", self.server_url).rstrip("/")
                        self.enrollment_token = data.get("enrollment_token", self.enrollment_token)
                        self.device_id = data.get("device_id")
                        self.device_credential = data.get("device_credential")
                        logger.info(f"Loaded persistent config from {p}")
                        return
                except Exception as e:
                    logger.warning(f"Failed to read config from {p}: {e}")

    def save(self):
        data = {
            "server_url": self.server_url,
            "device_id": self.device_id,
            "device_credential": self.device_credential,
            "saved_at": datetime.now(timezone.utc).isoformat()
        }
        try:
            with open(self.file_path, "w") as f:
                json.dump(data, f, indent=2)
            logger.info(f"Saved persistent agent config to {self.file_path}")
        except Exception as e:
            # Fallback to local
            with open("agent_config.json", "w") as f:
                json.dump(data, f, indent=2)
            logger.info("Saved config to local agent_config.json")

def get_mac_address() -> str:
    mac = uuid.UUID(int=uuid.getnode()).hex[-12:]
    return ":".join([mac[e:e+2] for e in range(0, 11, 2)])

def get_ip_address() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

class HTTPTransport:
    def __init__(self, config: AgentConfig):
        self.config = config

    def post(self, endpoint: str, payload: dict, auth: bool = True) -> Optional[dict]:
        url = f"{self.config.server_url}/api/v1{endpoint}"
        body = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(url, data=body, headers={'Content-Type': 'application/json'})
        
        if auth and self.config.device_credential:
            req.add_header('Authorization', f"Bearer {self.config.device_credential}")

        try:
            with urllib.request.urlopen(req, timeout=8) as res:
                if res.status in (200, 201):
                    return json.loads(res.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            logger.error(f"HTTP error on {endpoint}: {e.code} - {e.reason}")
        except Exception as e:
            logger.warning(f"Connection failure to {url}: {e}")
        return None

def collect_telemetry(device_id: str) -> dict:
    cpu = 0.0
    mem_pct = 0.0
    mem_used = 0
    mem_total = 1024
    disk_pct = 0.0
    rx_bytes = 0
    tx_bytes = 0

    try:
        import psutil
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()
        mem_pct = mem.percent
        mem_used = int(mem.used / (1024 * 1024))
        mem_total = int(mem.total / (1024 * 1024))
        disk = psutil.disk_usage('/') if platform.system() != 'Windows' else psutil.disk_usage('C:\\')
        disk_pct = disk.percent
        net = psutil.net_io_counters()
        rx_bytes = net.bytes_recv
        tx_bytes = net.bytes_sent
    except ImportError:
        # Native Linux fallback
        if platform.system() == "Linux":
            try:
                with open("/proc/loadavg", "r") as f:
                    cpu = min(100.0, float(f.read().split()[0]) * 25.0)
                with open("/proc/meminfo", "r") as f:
                    lines = f.readlines()
                    total = int([l for l in lines if "MemTotal" in l][0].split()[1]) // 1024
                    free = int([l for l in lines if "MemAvailable" in l][0].split()[1]) // 1024
                    mem_total = total
                    mem_used = total - free
                    mem_pct = round((mem_used / max(1, total)) * 100, 1)
            except Exception:
                pass

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "device_id": device_id,
        "cpu_percent": float(cpu),
        "memory_percent": float(mem_pct),
        "memory_used_mb": int(mem_used),
        "memory_total_mb": int(mem_total),
        "disk_percent": float(disk_pct),
        "network_rx_bytes": int(rx_bytes),
        "network_tx_bytes": int(tx_bytes)
    }

def collect_processes(device_id: str) -> list:
    procs = []
    try:
        import psutil
        for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'exe', 'username']):
            try:
                info = p.info
                procs.append({
                    "pid": info['pid'],
                    "name": info['name'] or 'unknown',
                    "cpu_percent": float(info['cpu_percent'] or 0.0),
                    "memory_percent": float(info['memory_percent'] or 0.0),
                    "executable": info['exe'] or '',
                    "username": info['username'] or ''
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            if len(procs) >= 50:
                break
    except Exception:
        pass
    return procs

def collect_system_logs(device_id: str, os_name: str) -> list:
    logs = []
    now_str = datetime.now(timezone.utc).isoformat()

    if os_name == "linux":
        try:
            cmd = ["journalctl", "-o", "json", "-n", "8", "--no-pager"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            for line in res.stdout.strip().split('\n'):
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                    syslog_id = ev.get("SYSLOG_IDENTIFIER", "system")
                    prio = int(ev.get("PRIORITY", "6"))
                    sev = "error" if prio <= 3 else "warning" if prio == 4 else "information"
                    logs.append({
                        "timestamp": now_str,
                        "device_id": device_id,
                        "os": "linux",
                        "source_type": "journald",
                        "source": syslog_id,
                        "event_id": syslog_id,
                        "event_type": "system",
                        "severity": sev,
                        "message": ev.get("MESSAGE", ""),
                        "raw_log": line
                    })
                except Exception:
                    pass
        except Exception:
            pass

    elif os_name == "windows":
        try:
            # Query recent Windows Application/System event logs using built-in wevtutil
            cmd = ["wevtutil", "qe", "System", "/c:5", "/rd:true", "/f:text"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if res.stdout:
                chunks = [c.strip() for c in res.stdout.strip().split("\n\r\n") if c.strip()]
                if not chunks:
                    chunks = [c.strip() for c in res.stdout.strip().split("\n\n") if c.strip()]
                for chunk in chunks[:5]:
                    lines = chunk.splitlines()
                    first_line = lines[0] if lines else "Windows System Event"
                    logs.append({
                        "timestamp": now_str,
                        "device_id": device_id,
                        "os": "windows",
                        "source_type": "eventlog",
                        "source": "System",
                        "event_id": "SystemEvent",
                        "event_type": "system",
                        "severity": "information",
                        "message": first_line[:200],
                        "raw_log": chunk[:1000]
                    })
        except Exception:
            pass

    return logs

_seen_dns_records: Dict[tuple, float] = {}
_seen_web_visits: Dict[tuple, float] = {}
_dns_ip_to_domain: Dict[str, str] = {}
_reverse_dns_cache: Dict[str, str] = {}

_NOISE_DOMAINS = (
    ".in-addr.arpa", ".local", ".lan", "wpad",
    "telemetry.microsoft.com", "events.data.microsoft.com", "wns.windows.com",
    "pipe.aria.microsoft.com", "settings-win.data.microsoft.com", "trafficmanager.net",
    "vortex.data.microsoft.com", "msftconnecttest.com", "msftncsi.com",
    "delivery.mp.microsoft.com", "update.microsoft.com", "windowsupdate.com",
    "smartscreen.microsoft.com", "activity.windows.com"
)

def get_domain_for_ip(ip: str) -> str:
    """Resolves IP to domain using DNS cache lookup or fast reverse DNS PTR."""
    if not ip or ip in ("127.0.0.1", "0.0.0.0", "::1") or ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
        return ""
    if ip in _dns_ip_to_domain:
        return _dns_ip_to_domain[ip]
    if ip in _reverse_dns_cache:
        return _reverse_dns_cache[ip]
    try:
        orig_to = socket.getdefaulttimeout()
        socket.setdefaulttimeout(0.7)
        host, _, _ = socket.gethostbyaddr(ip)
        socket.setdefaulttimeout(orig_to)
        # Simplify Google infrastructure domains
        clean_host = host
        if "1e100.net" in host.lower():
            clean_host = "youtube.com / google.com"
        _reverse_dns_cache[ip] = clean_host
        return clean_host
    except Exception:
        _reverse_dns_cache[ip] = ""
        return ""

def collect_dns_and_web_logs(device_id: str, os_name: str) -> list:
    """
    Extracts queried website domains and DNS resolutions from endpoint OS.
    Windows: Inspects DNS Client Cache via ipconfig /displaydns and Get-DnsClientCache.
    Linux: Reads /etc/hosts and resolves active outbound sockets.
    Emits distinct 'DNS_QUERY' logs showing the actual website (e.g. youtube.com).
    """
    dns_logs = []
    now = time.time()
    now_str = datetime.now(timezone.utc).isoformat()

    # Clean old seen records every 30 minutes
    if len(_seen_dns_records) > 3000:
        cutoff = now - 1800
        for k in list(_seen_dns_records.keys()):
            if _seen_dns_records[k] < cutoff:
                del _seen_dns_records[k]

    if os_name == "windows":
        pairs = []
        # Attempt 1: Fast ipconfig /displaydns (universal on all Windows versions)
        try:
            res = subprocess.run(["ipconfig", "/displaydns"], capture_output=True, text=True, timeout=5)
            if res.stdout:
                blocks = re.split(r"-{8,}", res.stdout)
                for b in blocks:
                    name_m = re.search(r"Record Name[ .\t]*:[ \t]*([^\r\n]+)", b, re.IGNORECASE)
                    ip_m = re.search(r"A \(IPv4\) Record[ .\t]*:[ \t]*([0-9\.]+)", b, re.IGNORECASE)
                    if name_m and ip_m:
                        dom = name_m.group(1).strip().rstrip(".").lower()
                        ip_val = ip_m.group(1).strip()
                        if (
                            dom and "." in dom
                            and not any(nd in dom for nd in _NOISE_DOMAINS)
                            and ip_val not in ("127.0.0.1", "0.0.0.0", "255.255.255.255")
                        ):
                            pairs.append((dom, ip_val))
        except Exception:
            pass

        # Attempt 2: PowerShell Get-DnsClientCache
        if not pairs:
            try:
                ps_cmd = 'Get-DnsClientCache | Where-Object { $_.Type -eq 1 -and $_.Status -eq 0 -and $_.Data } | Select-Object -Property Entry, Data | ConvertTo-Json'
                res = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd], capture_output=True, text=True, timeout=6)
                if res.stdout.strip():
                    data = json.loads(res.stdout)
                    items = data if isinstance(data, list) else [data]
                    for it in items:
                        dom = str(it.get("Entry", "")).strip().rstrip(".").lower()
                        ip_val = str(it.get("Data", "")).strip()
                        if dom and ip_val and "." in dom and not any(nd in dom for nd in _NOISE_DOMAINS):
                            pairs.append((dom, ip_val))
            except Exception:
                pass

        # Prioritize real user browsing domains (YouTube, Google, Reddit, etc.) over background subdomains
        def domain_priority(pair):
            dom = pair[0]
            if any(k in dom for k in ("youtube", "google", "github", "reddit", "twitter", "x.com", "instagram", "netflix", "wikipedia", "spotify")):
                return 0
            if any(dom.endswith(tld) for tld in (".com", ".org", ".net", ".io", ".in", ".co", ".app", ".dev", ".ai")):
                return 1
            return 2

        pairs.sort(key=domain_priority)

        # Deduplicate and register new/active domain queries
        for dom, ip_val in pairs:
            _dns_ip_to_domain[ip_val] = dom
            pair_key = (dom, ip_val)
            if pair_key not in _seen_dns_records or (now - _seen_dns_records[pair_key] > 300):
                _seen_dns_records[pair_key] = now
                dns_logs.append({
                    "timestamp": now_str,
                    "device_id": device_id,
                    "os": "windows",
                    "source_type": "network",
                    "source": "dns_cache",
                    "event_id": "DNS_QUERY",
                    "event_type": "network",
                    "severity": "information",
                    "message": f"🌐 Website / Domain Visited: https://{dom} (Resolved IP: {ip_val})",
                    "raw_log": json.dumps({
                        "domain": dom,
                        "resolved_ip": ip_val,
                        "record_type": "A",
                        "source": "Windows DNS Client Cache",
                        "url_preview": f"https://{dom}"
                    })
                })
                if len(dns_logs) >= 35:
                    break

    elif os_name == "linux":
        try:
            # 1. Read static host mappings from /etc/hosts
            if os.path.exists("/etc/hosts"):
                with open("/etc/hosts", "r") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            parts = line.split()
                            if len(parts) >= 2:
                                hip = parts[0]
                                for hname in parts[1:]:
                                    hname = hname.lower()
                                    if "." in hname and not any(nd in hname for nd in _NOISE_DOMAINS) and hip not in ("127.0.0.1", "::1"):
                                        _dns_ip_to_domain[hip] = hname
                                        pair_key = (hname, hip)
                                        if pair_key not in _seen_dns_records:
                                            _seen_dns_records[pair_key] = now
                                            dns_logs.append({
                                                "timestamp": now_str,
                                                "device_id": device_id,
                                                "os": "linux",
                                                "source_type": "network",
                                                "source": "dns_cache",
                                                "event_id": "DNS_QUERY",
                                                "event_type": "network",
                                                "severity": "information",
                                                "message": f"🌐 Host Mapping / Visited: https://{hname} (IP: {hip})",
                                                "raw_log": json.dumps({
                                                    "domain": hname,
                                                    "resolved_ip": hip,
                                                    "source": "/etc/hosts",
                                                    "url_preview": f"https://{hname}"
                                                })
                                            })
        except Exception:
            pass

    return dns_logs

def collect_network_logs(device_id: str, os_name: str) -> list:
    net_logs = []
    now = time.time()
    now_str = datetime.now(timezone.utc).isoformat()

    # 1. Collect real DNS queries and visited website domains from OS cache
    dns_logs = collect_dns_and_web_logs(device_id, os_name)
    net_logs.extend(dns_logs)

    # 2. Collect active socket connections with domain & process enrichment
    try:
        import psutil
        proc_names = {}
        for p in psutil.process_iter(['pid', 'name']):
            try:
                proc_names[p.info['pid']] = p.info['name']
            except Exception:
                pass

        conns = psutil.net_connections(kind='inet')
        for c in conns:
            if c.raddr:
                r_ip, r_port = c.raddr.ip, c.raddr.port
                l_ip, l_port = c.laddr.ip, c.laddr.port
                status = c.status
                proto = "tcp" if c.type == socket.SOCK_STREAM else "udp"
                pname = proc_names.get(c.pid, "unknown")
                # Filter out loopback connections
                if r_ip not in ("127.0.0.1", "::1", "0.0.0.0") and l_ip != r_ip:
                    matched_domain = get_domain_for_ip(r_ip)
                    domain_label = f" [Domain: {matched_domain}]" if matched_domain else ""
                    
                    # If outbound connection to web port (80, 443, 8080, 8443) with domain, emit a dedicated WEB_VISIT log!
                    if r_port in (80, 443, 8080, 8443) and matched_domain and not any(nd in matched_domain for nd in _NOISE_DOMAINS):
                        web_key = (matched_domain, r_port)
                        if web_key not in _seen_web_visits or (now - _seen_web_visits[web_key] > 180):
                            _seen_web_visits[web_key] = now
                            net_logs.append({
                                "timestamp": now_str,
                                "device_id": device_id,
                                "os": os_name,
                                "source_type": "network",
                                "source": "browser_network",
                                "event_id": "WEB_VISIT",
                                "event_type": "network",
                                "severity": "information",
                                "message": f"🌐 Visited Website: https://{matched_domain} (Remote IP: {r_ip}:{r_port}, Process: {pname})",
                                "raw_log": json.dumps({
                                    "domain": matched_domain,
                                    "resolved_ip": r_ip,
                                    "remote_port": r_port,
                                    "process": pname,
                                    "pid": c.pid,
                                    "url_preview": f"https://{matched_domain}"
                                })
                            })

                    net_logs.append({
                        "timestamp": now_str,
                        "device_id": device_id,
                        "os": os_name,
                        "source_type": "network",
                        "source": "kernel_socket",
                        "event_id": f"CONN_{status}",
                        "event_type": "network",
                        "severity": "information",
                        "message": f"{proto.upper()} {status}: {l_ip}:{l_port} -> {r_ip}:{r_port}{domain_label} ({pname} PID: {c.pid})",
                        "raw_log": json.dumps({
                            "protocol": proto,
                            "local_addr": f"{l_ip}:{l_port}",
                            "remote_addr": f"{r_ip}:{r_port}",
                            "status": status,
                            "process": pname,
                            "pid": c.pid,
                            "domain": matched_domain
                        })
                    })
            if len(net_logs) >= 40:
                break
    except Exception:
        # Fallback to netstat / ss
        if os_name == "windows":
            try:
                res = subprocess.run(["netstat", "-ano", "-p", "tcp"], capture_output=True, text=True, timeout=4)
                for line in res.stdout.strip().splitlines():
                    parts = line.strip().split()
                    if len(parts) >= 4 and parts[0] in ("TCP", "UDP"):
                        proto = parts[0]
                        laddr = parts[1]
                        raddr = parts[2]
                        state = parts[3] if len(parts) >= 5 else "ESTABLISHED"
                        pid = parts[-1]
                        if not raddr.startswith("0.0.0.0") and not raddr.startswith("[::]") and not raddr.startswith("127.0.0.1"):
                            r_ip = raddr.split(":")[0] if ":" in raddr else raddr
                            matched_domain = get_domain_for_ip(r_ip)
                            domain_label = f" [Domain: {matched_domain}]" if matched_domain else ""
                            net_logs.append({
                                "timestamp": now_str,
                                "device_id": device_id,
                                "os": "windows",
                                "source_type": "network",
                                "source": "netstat",
                                "event_id": f"CONN_{state}",
                                "event_type": "network",
                                "severity": "information",
                                "message": f"{proto} {state}: {laddr} -> {raddr}{domain_label} (PID: {pid})",
                                "raw_log": line.strip()
                            })
                            if len(net_logs) >= 30:
                                break
            except Exception:
                pass
        elif os_name == "linux":
            try:
                res = subprocess.run(["ss", "-tunp"], capture_output=True, text=True, timeout=3)
                for line in res.stdout.strip().splitlines()[1:20]:
                    parts = line.strip().split()
                    if len(parts) >= 5:
                        proto = parts[0].upper()
                        state = parts[1]
                        laddr = parts[4]
                        raddr = parts[5] if len(parts) > 5 else "*:*"
                        proc = parts[6] if len(parts) > 6 else ""
                        net_logs.append({
                            "timestamp": now_str,
                            "device_id": device_id,
                            "os": "linux",
                            "source_type": "network",
                            "source": "ss",
                            "event_id": f"CONN_{state}",
                            "event_type": "network",
                            "severity": "information",
                            "message": f"{proto} {state}: {laddr} -> {raddr} {proc}",
                            "raw_log": line.strip()
                        })
            except Exception:
                pass

    return net_logs

class SIEMAgentApp:
    def __init__(self):
        self.config = AgentConfig()
        self.transport = HTTPTransport(self.config)
        self.os_name = platform.system().lower()
        self.hostname = socket.gethostname()
        self.current_ip = get_ip_address()
        self.mac = get_mac_address()
        self.log_buffer = []

    def enroll_if_needed(self) -> bool:
        if self.config.device_id and self.config.device_credential:
            logger.info(f"Agent already permanently enrolled with Device ID: {self.config.device_id}")
            return True

        if not self.config.enrollment_token:
            logger.error("No credentials and no enrollment_token found in config. Cannot register.")
            return False

        logger.info(f"Registering endpoint '{self.hostname}' ({self.current_ip}) with {self.config.server_url}...")
        payload = {
            "token": self.config.enrollment_token,
            "hostname": self.hostname,
            "os": self.os_name,
            "os_version": platform.version(),
            "agent_version": "2.0.0",
            "mac_address": self.mac,
            "ip_address": self.current_ip
        }

        res = self.transport.post("/enrollment/register", payload, auth=False)
        if res and "device_id" in res:
            self.config.device_id = res["device_id"]
            self.config.device_credential = res["device_credential"]
            self.config.save()
            logger.info(f"[+] Enrollment SUCCESS! Permanent Device ID: {self.config.device_id}")
            return True
        else:
            logger.error("Enrollment failed. Will retry in 10 seconds...")
            return False

    def check_for_updates(self):
        """Checks SIEM server for updated agent code and hot-reloads if modified."""
        try:
            url = f"{self.config.server_url}/api/v1/enrollment/agent.py"
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=5) as res:
                if res.status == 200:
                    new_code = res.read().decode('utf-8')
                    current_file = os.path.abspath(__file__)
                    with open(current_file, 'r', encoding='utf-8') as f:
                        current_code = f.read()
                    if new_code and new_code.strip() != current_code.strip() and "SIEM Universal Endpoint Agent" in new_code:
                        logger.info("New agent code detected from SIEM server! Applying update...")
                        if platform.system() == "Windows":
                            # Windows file locking prevents overwriting the running script in-place.
                            # Write to .new and spawn detached cmd updater that swaps file and restarts.
                            update_file = current_file + ".new"
                            with open(update_file, 'w', encoding='utf-8') as f:
                                f.write(new_code)
                            bat_content = f"""@echo off
timeout /t 2 /nobreak >nul
copy /y "{update_file}" "{current_file}" >nul
del "{update_file}" >nul
start "" "{sys.executable}" "{current_file}"
del "%~f0" >nul
"""
                            bat_path = os.path.join(os.path.dirname(current_file), "update_agent.bat")
                            with open(bat_path, "w") as bf:
                                bf.write(bat_content)
                            flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
                            subprocess.Popen(["cmd.exe", "/c", bat_path], creationflags=flags)
                            logger.info("Detached Windows updater worker launched. Exiting current agent process.")
                            sys.exit(0)
                        else:
                            with open(current_file, 'w', encoding='utf-8') as f:
                                f.write(new_code)
                            logger.info("Agent updated successfully. Hot-restarting process...")
                            os.execv(sys.executable, [sys.executable, current_file])
        except Exception as e:
            logger.debug(f"Update check skipped: {e}")

    def run(self):
        logger.info(f"Starting SIEM Agent on {self.hostname} ({self.os_name})...")
        
        while not self.enroll_if_needed():
            time.sleep(10)

        logger.info("Entering persistent background telemetry loop.")
        last_heartbeat = 0
        last_metric = 0
        last_log = 0
        last_update_check = time.time()

        while True:
            now = time.time()

            # Dynamic network change detection
            fresh_ip = get_ip_address()
            if fresh_ip != self.current_ip:
                logger.info(f"Network interface change detected: {self.current_ip} -> {fresh_ip}")
                self.current_ip = fresh_ip
                # Force immediate heartbeat to update SIEM server's active network roster
                last_heartbeat = 0

            # 1. Heartbeat
            if now - last_heartbeat > self.config.heartbeat_interval:
                res = self.transport.post("/agent/heartbeat", {
                    "device_id": self.config.device_id,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "status": "online"
                })
                if res:
                    last_heartbeat = now
                else:
                    logger.warning("Heartbeat failed, server unreachable.")

            # 2. Metrics & Processes
            if now - last_metric > self.config.metric_interval:
                met = collect_telemetry(self.config.device_id)
                self.transport.post("/agent/metrics", {
                    "device_id": self.config.device_id,
                    "metrics": [met]
                })

                procs = collect_processes(self.config.device_id)
                if procs:
                    self.transport.post("/agent/processes", {
                        "device_id": self.config.device_id,
                        "processes": procs
                    })
                last_metric = now

            # 3. Logs (System & Network)
            if now - last_log > self.config.log_interval:
                sys_logs = collect_system_logs(self.config.device_id, self.os_name)
                net_logs = collect_network_logs(self.config.device_id, self.os_name)
                logs = sys_logs + net_logs
                # Combine with buffered logs
                if self.log_buffer:
                    logs.extend(self.log_buffer)
                    self.log_buffer = []

                if logs:
                    res = self.transport.post("/agent/logs", {
                        "device_id": self.config.device_id,
                        "logs": logs
                    })
                    if not res:
                        # Buffer failed logs (up to 200 items)
                        self.log_buffer = (self.log_buffer + logs)[-200:]
                        logger.warning(f"Log dispatch failed, buffered {len(self.log_buffer)} events.")
                last_log = now

            # 4. Periodic auto-update check every 60s
            if now - last_update_check > 60:
                self.check_for_updates()
                last_update_check = now

            time.sleep(1)

if __name__ == "__main__":
    agent = SIEMAgentApp()
    try:
        agent.run()
    except KeyboardInterrupt:
        logger.info("Agent stopped by user.")
        sys.exit(0)
    except Exception as e:
        logger.critical(f"Fatal agent exception: {e}", exc_info=True)
        sys.exit(1)
