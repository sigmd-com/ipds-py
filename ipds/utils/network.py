"""
Network utilities for IPDS
"""

import ipaddress
import socket
import subprocess
import platform
from typing import List, Dict, Any, Optional, Tuple


class NetworkUtils:
    """
    Network utility functions
    """
    
    def __init__(self):
        """Initialize network utils."""
        pass
    
    def ping(self, host: str, count: int = 4, timeout: int = 3) -> Dict[str, Any]:
        """
        Ping a host and return results.
        
        Args:
            host: Host to ping
            count: Number of ping packets
            timeout: Timeout in seconds
            
        Returns:
            Dictionary with ping results
        """
        try:
            if platform.system().lower() == "windows":
                cmd = ["ping", "-n", str(count), "-w", str(timeout * 1000), host]
            else:
                cmd = ["ping", "-c", str(count), "-W", str(timeout), host]
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=timeout + 5
            )
            
            if result.returncode == 0:
                output = result.stdout
                lines = output.split('\n')
                
                stats = {}
                for line in lines:
                    if 'packets transmitted' in line.lower():
                        parts = line.split(',')
                        for part in parts:
                            if 'packet loss' in part.lower():
                                stats['packet_loss'] = part.strip()
                    elif 'round-trip min/avg/max' in line.lower():
                        stats['timing'] = line.strip()
                    elif 'time=' in line.lower():
                        if 'times' not in stats:
                            stats['times'] = []
                        try:
                            time_part = line.split('time=')[1].split()[0]
                            stats['times'].append(float(time_part.replace('ms', '')))
                        except (IndexError, ValueError):
                            pass
                
                return {
                    "success": True,
                    "host": host,
                    "output": output,
                    "stats": stats,
                }
            else:
                return {
                    "success": False,
                    "host": host,
                    "error": result.stderr,
                    "returncode": result.returncode,
                }
                
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "host": host,
                "error": "Ping timeout",
            }
        except Exception as e:
            return {
                "success": False,
                "host": host,
                "error": str(e),
            }
    
    def traceroute(self, host: str, max_hops: int = 30) -> Dict[str, Any]:
        """
        Perform traceroute to a host.
        
        Args:
            host: Host to trace
            max_hops: Maximum number of hops
            
        Returns:
            Dictionary with traceroute results
        """
        try:
            if platform.system().lower() == "windows":
                cmd = ["tracert", "-h", str(max_hops), host]
            else:
                cmd = ["traceroute", "-m", str(max_hops), host]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                return {
                    "success": True,
                    "host": host,
                    "output": result.stdout,
                    "hops": self._parse_traceroute_output(result.stdout),
                }
            else:
                return {
                    "success": False,
                    "host": host,
                    "error": result.stderr,
                    "returncode": result.returncode,
                }
                
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "host": host,
                "error": "Traceroute timeout",
            }
        except Exception as e:
            return {
                "success": False,
                "host": host,
                "error": str(e),
            }
    
    def _parse_traceroute_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse traceroute output to extract hop information."""
        hops = []
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line or 'traceroute' in line.lower():
                continue
            
            if line[0].isdigit():
                parts = line.split()
                if len(parts) >= 2:
                    hop_num = parts[0]
                    ip = parts[1] if parts[1] != '*' else None
                    
                    hops.append({
                        "hop": int(hop_num),
                        "ip": ip,
                        "raw": line,
                    })
        
        return hops
    
    def reverse_dns(self, ip_address: str) -> Optional[str]:
        """
        Perform reverse DNS lookup.
        
        Args:
            ip_address: IP address to look up
            
        Returns:
            Hostname or None if not found
        """
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            return hostname
        except socket.herror:
            return None
        except Exception:
            return None
    
    def forward_dns(self, hostname: str) -> List[str]:
        """
        Perform forward DNS lookup.
        
        Args:
            hostname: Hostname to look up
            
        Returns:
            List of IP addresses
        """
        try:
            ip_addresses = socket.gethostbyname_ex(hostname)[2]
            return ip_addresses
        except socket.gaierror:
            return []
        except Exception:
            return []
    
    def get_local_ip(self) -> str:
        """
        Get local IP address.
        
        Returns:
            Local IP address
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
            return local_ip
        except Exception:
            return "127.0.0.1"
    
    def get_network_interfaces(self) -> List[Dict[str, Any]]:
        """
        Get network interfaces information.
        
        Returns:
            List of network interface information
        """
        interfaces = []
        
        try:
            import socket
            
            hostname = socket.gethostname()
            local_ip = self.get_local_ip()
            
            interfaces.append({
                "name": "default",
                "ip": local_ip,
                "hostname": hostname,
            })
            
        except Exception as e:
            interfaces.append({
                "name": "default",
                "error": str(e),
            })
        
        return interfaces
    
    def is_port_open(self, host: str, port: int, timeout: int = 3) -> bool:
        """
        Check if a port is open on a host.
        
        Args:
            host: Host to check
            port: Port to check
            timeout: Timeout in seconds
            
        Returns:
            True if port is open
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                result = s.connect_ex((host, port))
                return result == 0
        except Exception:
            return False
    
    def scan_ports(self, host: str, ports: List[int], timeout: int = 3) -> Dict[int, bool]:
        """
        Scan multiple ports on a host.
        
        Args:
            host: Host to scan
            ports: List of ports to scan
            timeout: Timeout per port
            
        Returns:
            Dictionary mapping port to open status
        """
        results = {}
        
        for port in ports:
            results[port] = self.is_port_open(host, port, timeout)
        
        return results
