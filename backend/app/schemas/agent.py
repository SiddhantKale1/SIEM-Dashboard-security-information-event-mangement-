from pydantic import BaseModel
from typing import List, Optional, Any
from datetime import datetime

class LogItem(BaseModel):
    timestamp: datetime
    device_id: str
    os: str
    source_type: str
    source: str
    event_id: Any
    event_type: str
    severity: str
    username: Optional[str] = None
    source_ip: Optional[str] = None
    message: Optional[str] = None
    raw_log: Optional[Any] = None

class LogsRequest(BaseModel):
    device_id: str
    logs: List[LogItem]

class MetricItem(BaseModel):
    timestamp: datetime
    device_id: str
    cpu_percent: float
    memory_percent: float
    memory_used_mb: int
    memory_total_mb: int
    disk_percent: float
    network_rx_bytes: int
    network_tx_bytes: int

class MetricsRequest(BaseModel):
    device_id: str
    metrics: List[MetricItem]

class ProcessItem(BaseModel):
    pid: int
    name: str
    cpu_percent: float
    memory_percent: float
    executable: Optional[str] = None
    username: Optional[str] = None

class ProcessesRequest(BaseModel):
    device_id: str
    processes: List[ProcessItem]
