import os
import json

class Settings:
    def __init__(self):
        self.CONFIG_FILE = "agent_config.json"
        self.SERVER_URL = os.environ.get("SERVER_URL", "http://127.0.0.1:8001")
        self.ENROLLMENT_TOKEN = os.environ.get("ENROLLMENT_TOKEN", "")
        self.HEARTBEAT_INTERVAL = int(os.environ.get("HEARTBEAT_INTERVAL", 30))
        self.METRIC_INTERVAL = int(os.environ.get("METRIC_INTERVAL", 10))
        self.LOG_INTERVAL = int(os.environ.get("LOG_INTERVAL", 5))
        
        # Will be populated after enrollment
        self.device_id = None
        self.device_credential = None
        self.load_config()

    def load_config(self):
        if os.path.exists(self.CONFIG_FILE):
            try:
                with open(self.CONFIG_FILE, "r") as f:
                    data = json.load(f)
                    self.device_id = data.get("device_id")
                    self.device_credential = data.get("device_credential")
            except Exception:
                pass

    def save_config(self, device_id, device_credential):
        self.device_id = device_id
        self.device_credential = device_credential
        with open(self.CONFIG_FILE, "w") as f:
            json.dump({"device_id": device_id, "device_credential": device_credential}, f)

settings = Settings()
