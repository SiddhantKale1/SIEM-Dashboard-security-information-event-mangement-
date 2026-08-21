import subprocess
import platform
import logging
import socket
import threading

logger = logging.getLogger(__name__)

class NetworkDiscovery:
    @staticmethod
    def _ping_host(ip):
        # Silent ping to populate ARP cache
        try:
            cmd = ['ping', '-c', '1', '-W', '1', ip] if platform.system() != 'Windows' else ['ping', '-n', '1', '-w', '1000', ip]
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

    @staticmethod
    def active_scan():
        # Get local IP and derive /24 subnet
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            base_ip = '.'.join(local_ip.split('.')[:-1])
            
            logger.info(f"Starting active ping sweep on {base_ip}.0/24")
            
            threads = []
            # Ping first 254 addresses in a background thread blast
            for i in range(1, 255):
                ip = f"{base_ip}.{i}"
                if ip != local_ip:
                    t = threading.Thread(target=NetworkDiscovery._ping_host, args=(ip,))
                    threads.append(t)
                    t.start()
                    
            # Wait a brief moment for all pings to dispatch and populate ARP
            for t in threads:
                t.join(timeout=0.1)
                
            logger.info("Ping sweep complete.")
        except Exception as e:
            logger.error(f"Active scan failed: {e}")

    @staticmethod
    def get_arp_table(active_scan=False):
        if active_scan:
            NetworkDiscovery.active_scan()
        
        devices = []
        try:
            # Safe and non-aggressive: Just read the local ARP cache
            cmd = ["arp", "-a"]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                if not line:
                    continue
                    
                # Parsing arp -a output varies by OS
                # Linux typical format: ? (192.168.1.1) at 00:11:22:33:44:55 [ether] on eth0
                # Windows typical format: 192.168.1.1       00-11-22-33-44-55     dynamic
                
                parts = line.split()
                if len(parts) >= 3:
                    ip = None
                    mac = None
                    
                    if platform.system() == 'Windows':
                        if len(parts) >= 3 and parts[1].count('-') == 5:
                            ip = parts[0]
                            mac = parts[1].replace('-', ':').lower()
                    else:
                        # Linux
                        if '(' in line and ')' in line:
                            start = line.find('(') + 1
                            end = line.find(')')
                            ip = line[start:end]
                            
                            # Find MAC
                            for p in parts:
                                if p.count(':') == 5 and len(p) == 17:
                                    mac = p.lower()
                                    break
                                    
                    if ip and mac and mac != 'ff:ff:ff:ff:ff:ff':
                        devices.append({
                            "ip_address": ip,
                            "mac_address": mac,
                            "hostname": "Unknown",
                            "os": "unknown",
                            "status": "discovered"
                        })
        except Exception as e:
            logger.error(f"Error reading ARP table: {e}")
            
        return devices
