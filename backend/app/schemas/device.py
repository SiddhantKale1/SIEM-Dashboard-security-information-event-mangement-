from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional

class DeviceBase(BaseModel):
    hostname: str
    ip_address: str
    mac_address: str
    os: str
    os_version: str
    agent_version: str

class DeviceCreate(DeviceBase):
    device_id: str

class DeviceResponse(DeviceBase):
    device_id: str
    status: str
    last_seen: datetime
    enrolled_at: datetime
    created_at: datetime

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class UserLogin(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    username: str
    role: str
