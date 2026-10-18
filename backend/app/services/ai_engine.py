import logging
import re
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

# --- MITRE ATT&CK Mapping & Threat Signatures ---
MITRE_TACTICS = {
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown.",
        "url": "https://attack.mitre.org/techniques/T1110/"
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters (e.g. bash, powershell) to execute commands.",
        "url": "https://attack.mitre.org/techniques/T1059/"
    },
    "T1548": {
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may circumvent mechanisms designed to control elevation of privileges to gain higher-level permissions.",
        "url": "https://attack.mitre.org/techniques/T1548/"
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts (e.g. nmap, port scans).",
        "url": "https://attack.mitre.org/techniques/T1046/"
    },
    "T1496": {
        "name": "Resource Hijacking (Cryptomining)",
        "tactic": "Impact",
        "description": "Adversaries may leverage computer resources for unauthorized purposes such as cryptocurrency mining.",
        "url": "https://attack.mitre.org/techniques/T1496/"
    },
    "T1562": {
        "name": "Impair Defenses",
        "tactic": "Defense Evasion",
        "description": "Adversaries may disable security tools, firewalls, or logging systems to avoid detection.",
        "url": "https://attack.mitre.org/techniques/T1562/"
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "description": "Adversaries may steal data by exfiltrating it over unusual network streams or burst channels.",
        "url": "https://attack.mitre.org/techniques/T1048/"
    }
}

class AIEngine:
    """
    AI-Driven Real-Time Security Monitoring & Anomaly Detection Engine.
    Performs multi-signal analysis on incoming logs, host telemetry, and processes.
    Generates structured AI incident investigations, risk scores, and MITRE ATT&CK classifications.
    """

    # In-memory sliding windows for rate-based anomaly detection (per host / source)
    _failed_logins: Dict[str, List[datetime]] = {}
    _metric_baselines: Dict[str, Dict[str, Any]] = {}

    @classmethod
    async def analyze_logs(
        cls, 
        db, 
        device_id: str, 
        hostname: str, 
        logs: List[Dict[str, Any]],
        ip_address: str = "127.0.0.1",
        os_name: str = "unknown"
    ) -> List[Dict[str, Any]]:
        """
        Real-time log stream inspection.
        Detects credential brute-force, unauthorized privilege escalations, suspicious commands, and defense evasion.
        """
        anomalies_detected = []
        now = datetime.now(timezone.utc)

        for log in logs:
            msg = str(log.get("message", "")).lower()
            source = str(log.get("source", "")).lower()
            event_id = str(log.get("event_id", ""))
            raw = str(log.get("raw_log", "")).lower()
            combined_text = f"{msg} {source} {raw}"

            # 1. SSH / Auth Brute Force Detection (MITRE T1110)
            is_auth_failure = (
                "failed password" in combined_text or
                "authentication failure" in combined_text or
                "failed logon" in combined_text or
                event_id in ["4625", "sshd"] and "fail" in combined_text or
                "invalid user" in combined_text
            )

            if is_auth_failure:
                host_key = f"{device_id}:auth_fail"
                cls._failed_logins.setdefault(host_key, [])
                cls._failed_logins[host_key].append(now)
                # Prune older than 90 seconds
                cutoff = now - timedelta(seconds=90)
                cls._failed_logins[host_key] = [t for t in cls._failed_logins[host_key] if t > cutoff]

                failure_count = len(cls._failed_logins[host_key])
                if failure_count >= 3:
                    # Extract attacker IP if present
                    ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", combined_text)
                    attacker_ip = ip_match.group(1) if ip_match else "External / Network"

                    anomaly = cls._build_anomaly(
                        device_id=device_id,
                        hostname=hostname,
                        title=f"Authentication Brute-Force Wave Detected ({failure_count} failures in 90s)",
                        severity="high" if failure_count < 6 else "critical",
                        confidence=96,
                        mitre_id="T1110",
                        summary=f"Automated credential brute-force surge detected on {hostname} ({ip_address}). Multiple consecutive failed logon attempts originated from {attacker_ip}.",
                        root_cause=f"High-frequency failed logon burst detected in auth logs. Pattern matches dictionary attack or automated SSH/RDP credential spraying.",
                        evidence=[
                            f"Detected {failure_count} failed login events within sliding 90s window",
                            f"Sample log: {log.get('message', '')[:140]}",
                            f"Target Service: {source or 'sshd/security'}",
                            f"Source IP: {attacker_ip}"
                        ],
                        recommended_action=f"1. Consider isolating endpoint {hostname} ({ip_address}) via 1-click quarantine. 2. Block offending IP {attacker_ip} at edge firewall. 3. Audit targeted account credentials.",
                        ip_address=ip_address,
                        os_name=os_name
                    )
                    anomalies_detected.append(anomaly)
                    # Reset counter to avoid duplicate firing
                    cls._failed_logins[host_key] = []

            # 2. Privilege Escalation & Sensitive File Tampering (MITRE T1548)
            is_priv_esc = (
                "sudo" in combined_text and ("chmod 777" in combined_text or "/etc/shadow" in combined_text or "/etc/sudoers" in combined_text) or
                "useradd" in combined_text and "root" in combined_text or
                "passwd root" in combined_text or
                "pkexec" in combined_text and "pwn" in combined_text or
                "su: auth failure" in combined_text
            )

            if is_priv_esc:
                anomaly = cls._build_anomaly(
                    device_id=device_id,
                    hostname=hostname,
                    title="Suspicious Privilege Escalation / Sensitive File Access",
                    severity="critical",
                    confidence=94,
                    mitre_id="T1548",
                    summary=f"A command attempted to escalate privileges or modify protected system security files on {hostname} ({ip_address}).",
                    root_cause="User or spawned subshell attempted modification of critical authentication tables (/etc/shadow or sudoers permissions).",
                    evidence=[
                        f"Triggering command/log: {log.get('message', '')[:160]}",
                        f"Source subsystem: {source}",
                        f"Execution timestamp: {now.isoformat()}"
                    ],
                    recommended_action=f"1. Isolate device {hostname} immediately. 2. Terminate the active TTY session. 3. Review /etc/passwd and sudoers integrity.",
                    ip_address=ip_address,
                    os_name=os_name
                )
                anomalies_detected.append(anomaly)

            # 3. Reverse Shell & Suspicious Script Execution (MITRE T1059)
            is_reverse_shell = (
                "/dev/tcp/" in combined_text or
                "nc -e" in combined_text or
                "ncat -e" in combined_text or
                "mkfifo" in combined_text and "sh" in combined_text or
                "curl" in combined_text and "| bash" in combined_text or
                "wget" in combined_text and "| sh" in combined_text or
                "powershell -enc" in combined_text or
                "powershell.exe -w hidden" in combined_text
            )

            if is_reverse_shell:
                anomaly = cls._build_anomaly(
                    device_id=device_id,
                    hostname=hostname,
                    title="Interactive Reverse Shell / Piped Execution Payload",
                    severity="critical",
                    confidence=98,
                    mitre_id="T1059",
                    summary=f"Suspicious interactive reverse-shell or pipe-to-shell payload execution detected on host {hostname} ({ip_address}).",
                    root_cause="Process spawned an unencrypted interactive socket or downloaded remote code directly into an interpreter shell.",
                    evidence=[
                        f"Signature match: {log.get('message', '')[:160]}",
                        f"Execution Environment: {log.get('os', os_name)}",
                        f"Subsystem: {source}"
                    ],
                    recommended_action=f"1. Isolate host {hostname} immediately from network. 2. Kill spawned parent PID and socket connection. 3. Inspect temporary directories.",
                    ip_address=ip_address,
                    os_name=os_name
                )
                anomalies_detected.append(anomaly)

            # 4. Impair Defenses / Firewall Tampering (MITRE T1562)
            is_defense_impairment = (
                "ufw disable" in combined_text or
                "iptables -f" in combined_text or
                "setenforce 0" in combined_text or
                "netsh advfirewall set" in combined_text and "off" in combined_text or
                "stop-service windefend" in combined_text or
                "systemctl stop auditd" in combined_text
            )

            if is_defense_impairment:
                anomaly = cls._build_anomaly(
                    device_id=device_id,
                    hostname=hostname,
                    title="Host Defense Impairment / Firewall Disabled",
                    severity="high",
                    confidence=95,
                    mitre_id="T1562",
                    summary=f"Host security defenses or local packet filter disabled on {hostname} ({ip_address}).",
                    root_cause="Local administration command or unauthorized script deliberately stopped host firewall or audit daemon.",
                    evidence=[
                        f"Action: {log.get('message', '')[:140]}",
                        f"Target Service: {source}"
                    ],
                    recommended_action=f"1. Re-enable firewall on {hostname} immediately. 2. Verify identity of administrator user executing the command.",
                    ip_address=ip_address,
                    os_name=os_name
                )
                anomalies_detected.append(anomaly)

        # Store detected anomalies into MongoDB
        if anomalies_detected:
            await db.anomalies.insert_many(anomalies_detected)
            logger.warning(f"AI Engine flagged {len(anomalies_detected)} security anomalies on host {hostname} ({device_id})")

        return anomalies_detected

    @classmethod
    async def analyze_metrics(
        cls, 
        db, 
        device_id: str, 
        hostname: str, 
        metrics: List[Dict[str, Any]],
        ip_address: str = "127.0.0.1",
        os_name: str = "unknown"
    ) -> List[Dict[str, Any]]:
        """
        Statistical metric anomaly detection.
        Detects cryptomining CPU surges, memory exhaustion, and unusual network exfiltration spikes.
        """
        anomalies_detected = []
        now = datetime.now(timezone.utc)

        for m in metrics:
            cpu = float(m.get("cpu_percent", 0.0))
            mem = float(m.get("memory_percent", 0.0))
            tx = int(m.get("network_tx_bytes", 0))

            # Maintain rolling baseline
            b = cls._metric_baselines.setdefault(device_id, {
                "cpu_history": [],
                "tx_history": [],
                "last_tx": tx
            })

            b["cpu_history"].append(cpu)
            if len(b["cpu_history"]) > 20:
                b["cpu_history"].pop(0)

            # 1. Sustained High-CPU Cryptominer Anomaly (MITRE T1496)
            avg_cpu = sum(b["cpu_history"]) / len(b["cpu_history"])
            high_count = len([x for x in b["cpu_history"][-5:] if x > 85.0])
            if cpu > 88.0 and (avg_cpu > 70.0 or high_count >= 3):
                anomaly = cls._build_anomaly(
                    device_id=device_id,
                    hostname=hostname,
                    title="Abnormal Sustained CPU Spike (Cryptomining Signature)",
                    severity="high",
                    confidence=89,
                    mitre_id="T1496",
                    summary=f"Host {hostname} ({ip_address}) is running at sustained high CPU ({cpu:.1f}%), indicating possible cryptojacking or rogue computation.",
                    root_cause=f"Host metric telemetry exceeded baseline threshold. Average CPU sustained at {avg_cpu:.1f}% across recent reporting cycles.",
                    evidence=[
                        f"Instantaneous CPU: {cpu:.1f}%",
                        f"20-sample Rolling Baseline: {avg_cpu:.1f}%",
                        f"Memory Utilization: {mem:.1f}%"
                    ],
                    recommended_action="1. Inspect running processes on endpoint for unknown binaries (e.g. xmrig, minerd). 2. Restrict outbound mining pool ports (3333, 4444, 5555).",
                    ip_address=ip_address,
                    os_name=os_name
                )
                anomalies_detected.append(anomaly)

            # 2. Exfiltration / Network Outbound Surge (MITRE T1048)
            prev_tx = b.get("last_tx", tx)
            tx_delta = max(0, tx - prev_tx)
            b["last_tx"] = tx
            b["tx_history"].append(tx_delta)
            if len(b["tx_history"]) > 20:
                b["tx_history"].pop(0)

            avg_tx = (sum(b["tx_history"]) / len(b["tx_history"])) if b["tx_history"] else 0
            # If outbound delta > 50MB in a single cycle or > 10x baseline
            if tx_delta > 50 * 1024 * 1024 or (avg_tx > 0 and tx_delta > 10 * avg_tx and tx_delta > 15 * 1024 * 1024):
                mb_transferred = tx_delta / (1024 * 1024)
                anomaly = cls._build_anomaly(
                    device_id=device_id,
                    hostname=hostname,
                    title=f"Massive Outbound Network Traffic Burst ({mb_transferred:.1f} MB)",
                    severity="high",
                    confidence=87,
                    mitre_id="T1048",
                    summary=f"Unusual burst of outbound network traffic detected from {hostname} ({ip_address}). Potential active data exfiltration.",
                    root_cause=f"Outbound transmission delta of {mb_transferred:.1f} MB significantly exceeds normal host telemetry baseline.",
                    evidence=[
                        f"Current TX Delta: {mb_transferred:.2f} MB",
                        f"Historical Average Delta: {avg_tx / (1024*1024):.2f} MB",
                        f"Burst Factor: {tx_delta / max(1, avg_tx):.1f}x baseline"
                    ],
                    recommended_action="1. Inspect active network sockets via netstat/ss on host. 2. Identify destination IP and port. 3. Isolate host if destination is untrusted.",
                    ip_address=ip_address,
                    os_name=os_name
                )
                anomalies_detected.append(anomaly)

        if anomalies_detected:
            await db.anomalies.insert_many(anomalies_detected)
            logger.warning(f"AI Engine flagged {len(anomalies_detected)} metric anomalies on host {hostname}")

        return anomalies_detected

    @classmethod
    async def analyze_processes(
        cls, 
        db, 
        device_id: str, 
        hostname: str, 
        processes: List[Dict[str, Any]],
        ip_address: str = "127.0.0.1",
        os_name: str = "unknown"
    ) -> List[Dict[str, Any]]:
        """
        Inspect process lists for known malware tools, scanners, and rogue utilities.
        """
        anomalies_detected = []
        suspicious_process_names = {
            "xmrig": ("T1496", "high", "Cryptocurrency miner daemon"),
            "minerd": ("T1496", "high", "Cryptocurrency miner daemon"),
            "nmap": ("T1046", "medium", "Network port scanning tool"),
            "masscan": ("T1046", "medium", "High-speed network scanner"),
            "mimikatz": ("T1110", "critical", "Credential dumping utility"),
            "hydra": ("T1110", "high", "Network logon cracking tool"),
            "john": ("T1110", "medium", "Password hash cracking tool"),
            "hashcat": ("T1110", "medium", "Password cracking tool"),
            "chisel": ("T1059", "high", "TCP/UDP tunnel over HTTP"),
            "ngrok": ("T1059", "medium", "Reverse proxy / tunnel")
        }

        for proc in processes:
            pname = str(proc.get("name", "")).lower()
            pexec = str(proc.get("executable", "")).lower()

            for target, (mitre_code, sev, desc) in suspicious_process_names.items():
                if target in pname or target in pexec:
                    anomaly = cls._build_anomaly(
                        device_id=device_id,
                        hostname=hostname,
                        title=f"Malicious / Dual-Use Tool Process Detected ({target})",
                        severity=sev,
                        confidence=95,
                        mitre_id=mitre_code,
                        summary=f"Endpoint {hostname} ({ip_address}) spawned a suspicious process: '{pname}' ({desc}).",
                        root_cause=f"Binary execution matches signature for {desc}.",
                        evidence=[
                            f"Process Name: {proc.get('name')}",
                            f"PID: {proc.get('pid')}",
                            f"Executable Path: {proc.get('executable')}",
                            f"CPU Percent: {proc.get('cpu_percent', 0)}%"
                        ],
                        recommended_action=f"1. Terminate PID {proc.get('pid')}. 2. Locate and quarantine executable file. 3. Investigate parent process lineage.",
                        ip_address=ip_address,
                        os_name=os_name
                    )
                    anomalies_detected.append(anomaly)

        if anomalies_detected:
            await db.anomalies.insert_many(anomalies_detected)
            logger.warning(f"AI Engine flagged {len(anomalies_detected)} process anomalies on host {hostname}")

        return anomalies_detected

    @staticmethod
    def _build_anomaly(
        device_id: str,
        hostname: str,
        title: str,
        severity: str,
        confidence: int,
        mitre_id: str,
        summary: str,
        root_cause: str,
        evidence: List[str],
        recommended_action: str,
        ip_address: str = "127.0.0.1",
        os_name: str = "unknown"
    ) -> Dict[str, Any]:
        mitre_info = MITRE_TACTICS.get(mitre_id, {
            "name": "Unknown",
            "tactic": "General",
            "description": "",
            "url": ""
        })

        # Explicitly prepend machine identification
        enriched_evidence = [
            f"Machine: {hostname} (IP: {ip_address}, OS: {os_name.capitalize()}, ID: {device_id})"
        ] + list(evidence)

        return {
            "device_id": device_id,
            "hostname": hostname,
            "ip_address": ip_address,
            "os": os_name,
            "title": f"[{hostname} - {ip_address}] {title}",
            "severity": severity,          # critical, high, medium, low
            "status": "active",             # active, investigating, resolved, false_positive
            "confidence": confidence,       # 0 - 100%
            "mitre_id": mitre_id,
            "mitre_technique": mitre_info["name"],
            "mitre_tactic": mitre_info["tactic"],
            "mitre_url": mitre_info["url"],
            "summary": summary,
            "root_cause": root_cause,
            "evidence": enriched_evidence,
            "recommended_action": recommended_action,
            "detected_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
            "resolved_at": None,
            "resolved_by": None
        }
