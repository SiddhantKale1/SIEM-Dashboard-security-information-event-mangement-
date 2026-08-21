import requests
import logging
import time
from config.settings import settings

logger = logging.getLogger(__name__)

class AgentClient:
    def __init__(self):
        self.session = requests.Session()
        self.buffer = []
        
    def get_headers(self):
        if not settings.device_credential:
            return {}
        return {"Authorization": f"Bearer {settings.device_credential}"}
        
    def register(self, hostname, os_name, mac, ip):
        url = f"{settings.SERVER_URL}/api/v1/enrollment/register"
        data = {
            "token": settings.ENROLLMENT_TOKEN,
            "hostname": hostname,
            "os": os_name,
            "mac_address": mac,
            "ip_address": ip,
            "os_version": "10",
            "agent_version": "1.0.0"
        }
        response = self.session.post(url, json=data)
        response.raise_for_status()
        result = response.json()
        settings.save_config(result["device_id"], result["device_credential"])
        logger.info(f"Registered successfully. Device ID: {settings.device_id}")
        return True
        
    def send_heartbeat(self):
        url = f"{settings.SERVER_URL}/api/v1/agent/heartbeat"
        data = {
            "device_id": settings.device_id,
            "timestamp": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            "status": "online"
        }
        response = self.session.post(url, json=data, headers=self.get_headers(), timeout=5)
        response.raise_for_status()
        
    def send_logs(self, logs):
        if not logs:
            return
        url = f"{settings.SERVER_URL}/api/v1/agent/logs"
        data = {
            "device_id": settings.device_id,
            "logs": logs
        }
        self._send_with_retry(url, data)
        
    def send_metrics(self, metrics):
        url = f"{settings.SERVER_URL}/api/v1/agent/metrics"
        data = {
            "device_id": settings.device_id,
            "metrics": [metrics]
        }
        self._send_with_retry(url, data)
        
    def send_processes(self, processes):
        url = f"{settings.SERVER_URL}/api/v1/agent/processes"
        data = {
            "device_id": settings.device_id,
            "processes": processes
        }
        self._send_with_retry(url, data)

    def _send_with_retry(self, url, data):
        # Implement buffering and exponential backoff for MVP
        try:
            response = self.session.post(url, json=data, headers=self.get_headers(), timeout=10)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            logger.warning(f"Failed to send data to {url}: {e}. Buffering data.")
            # In a full implementation, we would append to self.buffer and retry later.
            # For the MVP, we just log it. 
