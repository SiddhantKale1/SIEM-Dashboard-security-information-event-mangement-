import psutil
from datetime import datetime, timezone

def collect_telemetry(device_id):
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    net_io = psutil.net_io_counters()
    
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "device_id": device_id,
        "cpu_percent": cpu_percent,
        "memory_percent": memory.percent,
        "memory_used_mb": memory.used // (1024 * 1024),
        "memory_total_mb": memory.total // (1024 * 1024),
        "disk_percent": disk.percent,
        "network_rx_bytes": net_io.bytes_recv,
        "network_tx_bytes": net_io.bytes_sent
    }
