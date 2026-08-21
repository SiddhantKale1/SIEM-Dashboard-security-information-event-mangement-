import asyncio
import httpx
import os
import subprocess
import time

async def run_agent():
    async with httpx.AsyncClient(base_url="http://127.0.0.1:8002") as client:
        # Wait for backend
        await asyncio.sleep(2)
        
        # Login
        response = await client.post("/api/v1/auth/login", data={"username": "admin", "password": "admin"})
        token = response.json().get("access_token")
        
        # Get enrollment token
        headers = {"Authorization": f"Bearer {token}"}
        response = await client.post("/api/v1/enrollment/token", headers=headers)
        enrollment_token = response.json().get("token")
        print(f"Got enrollment token: {enrollment_token}")
        
        # Run agent
        env = os.environ.copy()
        env["ENROLLMENT_TOKEN"] = enrollment_token
        env["SERVER_URL"] = "http://127.0.0.1:8002"
        env["LOG_INTERVAL"] = "2"
        env["METRIC_INTERVAL"] = "2"
        env["HEARTBEAT_INTERVAL"] = "2"
        env["PYTHONPATH"] = "/home/sidd/SIEM/agents/windows"
        
        print("Starting Windows Agent...")
        process = subprocess.Popen(
            ["python", "agent.py"],
            cwd="/home/sidd/SIEM/agents/windows",
            env=env
        )
        
        # Let it run for 10 seconds to collect logs and metrics
        time.sleep(10)
        process.terminate()
        process.wait()
        print("Agent finished.")

if __name__ == "__main__":
    asyncio.run(run_agent())
