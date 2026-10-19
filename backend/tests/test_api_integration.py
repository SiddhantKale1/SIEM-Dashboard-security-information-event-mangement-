import pytest
import httpx
from httpx import ASGITransport
from datetime import datetime, timezone
from app.main import app
from app.database.connection import Database

@pytest.mark.asyncio
async def test_full_system_api_flow():
    await Database.connect_db()
    from app.auth.security import get_password_hash
    await Database.db.users.update_one(
        {"username": "admin"},
        {"$set": {"password_hash": get_password_hash("admin"), "role": "admin"}},
        upsert=True
    )
    transport = ASGITransport(app=app)
    
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. Health check
        res = await client.get("/health")
        assert res.status_code == 200
        assert res.json()["status"] == "ok"

        res_v1 = await client.get("/api/v1/health")
        assert res_v1.status_code == 200
        assert res_v1.json()["status"] == "ok"

        # 1b. Universal agent download
        agent_res = await client.get("/api/v1/enrollment/agent.py")
        assert agent_res.status_code == 200
        assert len(agent_res.content) > 1000

        # 2. Login as admin
        login_res = await client.post("/api/v1/auth/login", data={"username": "admin", "password": "admin"})
        assert login_res.status_code == 200
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 3. Create permanent fleet enrollment token
        token_res = await client.post("/api/v1/enrollment/token?reusable=true&days_valid=30", headers=headers)
        assert token_res.status_code == 200
        enroll_token = token_res.json()["token"]
        assert "install_commands" in token_res.json()
        assert "linux" in token_res.json()["install_commands"]
        assert "windows" in token_res.json()["install_commands"]

        # 4. Register permanent device
        reg_data = {
            "token": enroll_token,
            "hostname": "TEST-STATION-PRO",
            "os": "linux",
            "mac_address": "52:54:00:12:34:56",
            "ip_address": "192.168.1.120"
        }
        reg_res = await client.post("/api/v1/enrollment/register", json=reg_data)
        assert reg_res.status_code == 200
        dev_id = reg_res.json()["device_id"]
        dev_cred = reg_res.json()["device_credential"]
        dev_headers = {"Authorization": f"Bearer {dev_cred}"}

        # 5. Send agent heartbeat
        hb_data = {
            "device_id": dev_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "online"
        }
        hb_res = await client.post("/api/v1/agent/heartbeat", headers=dev_headers, json=hb_data)
        assert hb_res.status_code == 200

        # 6. Simulate cyber attack via Attack Simulator
        sim_res = await client.post("/api/v1/anomalies/simulate?scenario=ssh_brute_force", headers=headers)
        assert sim_res.status_code == 200
        assert sim_res.json()["anomalies_detected"] >= 1

        # 7. Check AI Threat Center
        threats_res = await client.get("/api/v1/anomalies?status=active", headers=headers)
        assert threats_res.status_code == 200
        anomalies = threats_res.json()["anomalies"]
        assert len(anomalies) >= 1
        assert any(a["mitre_id"] == "T1110" for a in anomalies)

        # 8. Check Network Traffic and Active Systems
        net_res = await client.get("/api/v1/network/active", headers=headers)
        assert net_res.status_code == 200
        assert "devices" in net_res.json()

        traffic_res = await client.get("/api/v1/network/traffic", headers=headers)
        assert traffic_res.status_code == 200
        assert "network" in traffic_res.json()

        history_res = await client.get("/api/v1/network/history", headers=headers)
        assert history_res.status_code == 200
        assert "history" in history_res.json()
        assert len(history_res.json()["history"]) >= 1

    await Database.close_db()
