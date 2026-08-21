from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class EnrollmentTokenResponse(BaseModel):
    token: str
    expires_at: datetime

class DeviceRegistrationRequest(BaseModel):
    token: str
    hostname: str
    os: str
    mac_address: str
    ip_address: str
    os_version: str = "unknown"
    agent_version: str = "1.0.0"

class DeviceRegistrationResponse(BaseModel):
    device_id: str
    device_credential: str

class HeartbeatRequest(BaseModel):
    device_id: str
    timestamp: datetime
    status: str
