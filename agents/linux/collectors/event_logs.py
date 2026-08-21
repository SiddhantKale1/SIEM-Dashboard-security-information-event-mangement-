import subprocess
import logging
from datetime import datetime, timezone
import json

logger = logging.getLogger(__name__)

class EventLogCollector:
    def __init__(self, device_id):
        self.device_id = device_id
        self.last_cursor = None
        
    def collect(self):
        logs = []
        try:
            # We use journalctl to fetch logs in JSON format for easy parsing
            cmd = ["journalctl", "-o", "json", "-n", "10", "--no-pager"]
            
            # In a real MVP we'd use --after-cursor=self.last_cursor to prevent reading old events
            if self.last_cursor:
                # cmd.extend(["--after-cursor", self.last_cursor])
                pass # For simplicity in this mock, we just take the last 10
                
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    
                    # Store cursor for next read
                    if "__CURSOR" in event:
                        self.last_cursor = event["__CURSOR"]
                        
                    # Extract timestamp
                    timestamp = datetime.now(timezone.utc).isoformat()
                    if "__REALTIME_TIMESTAMP" in event:
                        try:
                            ts_micro = int(event["__REALTIME_TIMESTAMP"])
                            timestamp = datetime.fromtimestamp(ts_micro / 1000000.0, timezone.utc).isoformat()
                        except ValueError:
                            pass
                            
                    syslog_id = event.get("SYSLOG_IDENTIFIER", "unknown")
                    priority = event.get("PRIORITY", "6")
                    message = event.get("MESSAGE", "")
                    
                    logs.append({
                        "timestamp": timestamp,
                        "device_id": self.device_id,
                        "os": "linux",
                        "source_type": "journald",
                        "source": syslog_id,
                        "event_id": syslog_id,
                        "event_type": "system",
                        "severity": self._map_severity(priority),
                        "message": message,
                        "raw_log": str(event)
                    })
                except json.JSONDecodeError:
                    pass
        except Exception as e:
            logger.error(f"Error reading journalctl logs: {e}")
            
        return logs
        
    def _map_severity(self, priority):
        # syslog priorities: 0=emerg, 1=alert, 2=crit, 3=err, 4=warning, 5=notice, 6=info, 7=debug
        try:
            pri = int(priority)
            if pri <= 3:
                return "error"
            elif pri == 4:
                return "warning"
            elif pri >= 5:
                return "information"
        except ValueError:
            pass
        return "unknown"
