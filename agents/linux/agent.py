import time
import socket
import platform
import uuid
import logging
import uuid
from config.settings import settings
from transport.client import AgentClient
from collectors.telemetry import collect_telemetry
from collectors.processes import collect_processes
from collectors.event_logs import EventLogCollector

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("LinuxAgent")

def get_mac_address():
    mac = uuid.UUID(int=uuid.getnode()).hex[-12:]
    return ":".join([mac[e:e+2] for e in range(0, 11, 2)])

def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

def main():
    logger.info("Starting Linux SIEM Agent...")
    client = AgentClient()
    
    if not settings.device_credential:
        if not settings.ENROLLMENT_TOKEN:
            logger.error("No device credential and no ENROLLMENT_TOKEN set. Cannot start.")
            return
            
        hostname = socket.gethostname()
        mac = get_mac_address()
        ip = get_ip_address()
        
        try:
            client.register(hostname, "linux", mac, ip)
        except Exception as e:
            logger.error(f"Enrollment failed: {e}")
            return
            
    logger.info(f"Agent running as Device ID: {settings.device_id}")
    
    event_collector = EventLogCollector(settings.device_id)
    
    last_heartbeat = 0
    last_metric = 0
    last_log = 0
    
    while True:
        now = time.time()
        
        try:
            # Heartbeat
            if now - last_heartbeat > settings.HEARTBEAT_INTERVAL:
                client.send_heartbeat()
                last_heartbeat = now
                logger.info("Heartbeat sent")
                
            # Metrics
            if now - last_metric > settings.METRIC_INTERVAL:
                metrics = collect_telemetry(settings.device_id)
                client.send_metrics(metrics)
                
                # Processes (send along with metrics for MVP)
                processes = collect_processes(settings.device_id)
                client.send_processes(processes)
                
                last_metric = now
                logger.info("Metrics and processes sent")
                
            # Logs
            if now - last_log > settings.LOG_INTERVAL:
                logs = event_collector.collect()
                if logs:
                    client.send_logs(logs)
                    logger.info(f"Sent {len(logs)} logs")
                last_log = now
                
        except Exception as e:
            logger.error(f"Error in main loop: {e}")
            
        time.sleep(1)

if __name__ == "__main__":
    main()
