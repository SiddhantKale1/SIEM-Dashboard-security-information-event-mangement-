import subprocess
import platform
import logging
import socket
import threading
import ipaddress
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

class NetworkManager:
    """
    Manages active network discovery, dynamic subnet scope,
    real-time traffic statistics, and persistent connection history.
    """

    @staticmethod
    def get_local_network_info() -> Dict[str, Any]:
        """
        Discovers local interface IP, subnet CIDR, and gateway info.
        """
        local_ip = "127.0.0.1"
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except Exception:
            try:
                local_ip = socket.gethostbyname(socket.gethostname())
            except Exception:
                local_ip = "127.0.0.1"

        try:
            # Assume /24 subnet for standard local area networks
            parts = local_ip.split('.')
            if len(parts) == 4 and parts[0] != "127":
                subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                gateway = f"{parts[0]}.{parts[1]}.{parts[2]}.1"
            else:
                subnet = "127.0.0.0/8"
                gateway = "127.0.0.1"
        except Exception:
            subnet = "192.168.1.0/24"
            gateway = "192.168.1.1"

        return {
            "server_ip": local_ip,
            "subnet": subnet,
            "gateway": gateway,
            "interface": "eth0" if platform.system() != "Windows" else "Ethernet/Wi-Fi",
            "detected_at": datetime.now(timezone.utc).isoformat()
        }

    @staticmethod
    def is_ip_in_subnet(ip: str, subnet_cidr: str) -> bool:
        """Checks if an IP address belongs to the current network subnet."""
        try:
            if ip in ["127.0.0.1", "localhost"]:
                return True
            net = ipaddress.ip_network(subnet_cidr, strict=False)
            return ipaddress.ip_address(ip) in net
        except Exception:
            return True

    @staticmethod
    def _ping_host(ip: str):
        try:
            cmd = ['ping', '-c', '1', '-W', '1', ip] if platform.system() != 'Windows' else ['ping', '-n', '1', '-w', '500', ip]
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

    @classmethod
    def active_scan_subnet(cls):
        """Sweeps local /24 subnet to refresh ARP table."""
        info = cls.get_local_network_info()
        base_ip = '.'.join(info["server_ip"].split('.')[:-1])
        if base_ip == "127.0.0":
            return

        threads = []
        for i in range(1, 255):
            target_ip = f"{base_ip}.{i}"
            if target_ip != info["server_ip"]:
                t = threading.Thread(target=cls._ping_host, args=(target_ip,))
                threads.append(t)
                t.start()

        for t in threads:
            t.join(timeout=0.08)

    @classmethod
    def get_arp_devices(cls, active_scan: bool = False) -> List[Dict[str, Any]]:
        """Reads local ARP cache to find live physical nodes on current network."""
        if active_scan:
            cls.active_scan_subnet()

        info = cls.get_local_network_info()
        current_subnet = info["subnet"]
        devices = []

        try:
            cmd = ["arp", "-a"]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)

            for line in result.stdout.strip().split('\n'):
                line = line.strip()
                if not line:
                    continue

                ip = None
                mac = None

                if platform.system() == 'Windows':
                    parts = line.split()
                    if len(parts) >= 3 and parts[1].count('-') == 5:
                        ip = parts[0]
                        mac = parts[1].replace('-', ':').lower()
                else:
                    if '(' in line and ')' in line:
                        start = line.find('(') + 1
                        end = line.find(')')
                        ip = line[start:end]
                        parts = line.split()
                        for p in parts:
                            if p.count(':') == 5 and len(p) == 17:
                                mac = p.lower()
                                break

                if ip and mac and mac != 'ff:ff:ff:ff:ff:ff':
                    # Only include if in current subnet
                    if cls.is_ip_in_subnet(ip, current_subnet):
                        devices.append({
                            "ip_address": ip,
                            "mac_address": mac,
                            "hostname": f"Host-{ip.split('.')[-1]}",
                            "subnet": current_subnet,
                            "status": "discovered"
                        })
        except Exception as e:
            logger.error(f"Error parsing ARP cache: {e}")

        return devices

    @classmethod
    async def record_connection_event(cls, db, device_id: str, hostname: str, ip: str, mac: str, os_name: str, event_type: str = "connected"):
        """
        Maintains persistent connection history in `db.connection_history`.
        When a device connects, checks if it has an existing active session.
        If moving from a different subnet, closes previous session and opens a new one.
        """
        now = datetime.now(timezone.utc)
        net_info = cls.get_local_network_info()
        current_subnet = net_info["subnet"]

        # Check existing active session for this device
        existing_session = await db.connection_history.find_one({
            "device_id": device_id,
            "status": "active"
        })

        if existing_session:
            # If IP or Subnet changed, close old session
            if existing_session.get("subnet") != current_subnet or existing_session.get("ip_address") != ip:
                conn_start = existing_session.get("connected_at", now)
                if isinstance(conn_start, datetime) and conn_start.tzinfo is None:
                    conn_start = conn_start.replace(tzinfo=timezone.utc)
                duration = int((now - conn_start).total_seconds()) if isinstance(conn_start, datetime) else 0
                filter_q = {"_id": existing_session["_id"]} if "_id" in existing_session else {"device_id": device_id, "status": "active"}
                await db.connection_history.update_one(
                    filter_q,
                    {"$set": {
                        "status": "closed",
                        "disconnected_at": now,
                        "duration_seconds": duration,
                        "termination_reason": "network_switch"
                    }}
                )
                existing_session = None

        if not existing_session and event_type == "connected":
            # Create new connection session
            session_doc = {
                "device_id": device_id,
                "hostname": hostname,
                "ip_address": ip,
                "mac_address": mac,
                "os": os_name,
                "subnet": current_subnet,
                "status": "active",
                "connected_at": now,
                "last_active_at": now,
                "disconnected_at": None,
                "duration_seconds": 0,
                "logs_sent": 0,
                "metrics_sent": 0,
                "termination_reason": None
            }
            await db.connection_history.insert_one(session_doc)
        elif existing_session:
            filter_q = {"_id": existing_session["_id"]} if "_id" in existing_session else {"device_id": device_id, "status": "active"}
            await db.connection_history.update_one(
                filter_q,
                {"$set": {"last_active_at": now}}
            )
