import pytest
import httpx
from httpx import ASGITransport
from datetime import datetime, timezone
from app.main import app
from app.database.connection import Database

@pytest.mark.asyncio
async def test_delete_device_cascade():
    await Database.connect_db()
    db = Database.db
    
    # 1. Setup admin user
    from app.auth.security import get_password_hash
    await db.users.update_one(
        {"username": "admin"},
        {"$set": {"password_hash": get_password_hash("admin"), "role": "admin"}},
        upsert=True
    )

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Authenticate
        login_res = await client.post("/api/v1/auth/login", data={"username": "admin", "password": "admin"})
        assert login_res.status_code == 200
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 2. Insert test device and related telemetry
        test_device_id = "device-del-test-1234"
        now = datetime.now(timezone.utc)

        await db.devices.delete_many({"device_id": test_device_id})
        await db.devices.insert_one({
            "device_id": test_device_id,
            "hostname": "DEL-TARGET-PC",
            "ip_address": "192.168.1.99",
            "mac_address": "00:11:22:33:44:55",
            "os": "linux",
            "status": "online",
            "last_seen": now,
            "created_at": now
        })

        await db.logs.insert_one({
            "device_id": test_device_id,
            "timestamp": now,
            "event_type": "auth",
            "message": "User logged in"
        })

        await db.metrics.insert_one({
            "device_id": test_device_id,
            "timestamp": now,
            "cpu_percent": 15.2
        })

        await db.processes.insert_one({
            "device_id": test_device_id,
            "timestamp": now,
            "processes": [{"pid": 100, "name": "bash"}]
        })

        await db.device_events.insert_one({
            "device_id": test_device_id,
            "event": "enrolled",
            "timestamp": now
        })

        await db.connection_history.insert_one({
            "device_id": test_device_id,
            "connected_at": now,
            "status": "active"
        })

        await db.anomalies.insert_one({
            "device_id": test_device_id,
            "anomaly_type": "high_cpu",
            "detected_at": now
        })

        # Verify device exists via API
        get_res = await client.get(f"/api/v1/devices/{test_device_id}", headers=headers)
        assert get_res.status_code == 200
        assert get_res.json()["hostname"] == "DEL-TARGET-PC"

        # 3. Call DELETE /api/v1/devices/{device_id}
        del_res = await client.delete(f"/api/v1/devices/{test_device_id}", headers=headers)
        assert del_res.status_code == 200
        del_json = del_res.json()
        assert del_json["status"] == "deleted"
        assert del_json["device_id"] == test_device_id

        # 4. Verify device is no longer found via API
        get_after = await client.get(f"/api/v1/devices/{test_device_id}", headers=headers)
        assert get_after.status_code == 404

        # 5. Verify cascade deletion across all collections
        assert await db.devices.find_one({"device_id": test_device_id}) is None
        assert await db.logs.find_one({"device_id": test_device_id}) is None
        assert await db.metrics.find_one({"device_id": test_device_id}) is None
        assert await db.processes.find_one({"device_id": test_device_id}) is None
        assert await db.device_events.find_one({"device_id": test_device_id}) is None
        assert await db.connection_history.find_one({"device_id": test_device_id}) is None
        assert await db.anomalies.find_one({"device_id": test_device_id}) is None

    await Database.close_db()
