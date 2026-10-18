import asyncio
import httpx

async def test_flow():
    async with httpx.AsyncClient(base_url="http://127.0.0.1:8001") as client:
        # Wait for server to start
        await asyncio.sleep(2)
        
        # 1. Login as admin
        response = await client.post("/api/v1/auth/login", data={"username": "admin", "password": "admin"})
        print("Login:", response.json())
        token = response.json().get("access_token")
        
        headers = {"Authorization": f"Bearer {token}"}
        
        # 2. Get enrollment token
        response = await client.post("/api/v1/enrollment/token", headers=headers)
        print("Enrollment Token:", response.json())
        enrollment_token = response.json().get("token")
        
        # 3. Register device
        device_data = {
            "token": enrollment_token,
            "hostname": "TEST-DESKTOP",
            "os": "windows",
            "mac_address": "00:11:22:33:44:55",
            "ip_address": "192.168.1.100"
        }
        response = await client.post("/api/v1/enrollment/register", json=device_data)
        print("Device Registration:", response.json())
        device_id = response.json().get("device_id")
        device_credential = response.json().get("device_credential")
        
        # 4. Agent Heartbeat
        device_headers = {"Authorization": f"Bearer {device_credential}"}
        heartbeat_data = {
            "device_id": device_id,
            "timestamp": "2026-08-16T16:30:00Z",
            "status": "online"
        }
        response = await client.post("/api/v1/agent/heartbeat", headers=device_headers, json=heartbeat_data)
        print("Agent Heartbeat:", response.json())

if __name__ == "__main__":
    asyncio.run(test_flow())
