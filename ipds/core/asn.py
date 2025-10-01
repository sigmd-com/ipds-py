"""
ASN (Autonomous System Number) lookup module.
"""

import ipaddress
import requests
import json
from typing import Dict, Any, Optional, List


class ASN:
    """
    ASN lookup for IP addresses.
    """
    
    def __init__(self):
        """Initialize ASN service."""
        self.base_urls = {
            "ipapi": "http://ip-api.com/json/",
            "ipinfo": "https://ipinfo.io/",
            "hackertarget": "https://api.hackertarget.com/aslookup/",
        }
    
    def lookup(self, ip_address: str, service: str = "ipapi") -> Dict[str, Any]:
        """
        Look up ASN information for an IP address.
        
        Args:
            ip_address: IP address to look up
            service: Service to use for lookup
            
        Returns:
            Dictionary with ASN information
        """
        try:
            if service == "ipapi":
                return self._lookup_ipapi(ip_address)
            elif service == "ipinfo":
                return self._lookup_ipinfo(ip_address)
            elif service == "hackertarget":
                return self._lookup_hackertarget(ip_address)
            else:
                raise ValueError(f"Unknown service: {service}")
        except Exception as e:
            return {"error": f"ASN lookup failed: {str(e)}"}
    
    def _lookup_ipapi(self, ip_address: str) -> Dict[str, Any]:
        """Look up using ip-api.com service."""
        try:
            url = f"{self.base_urls['ipapi']}{ip_address}"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            
            as_info = data.get("as", "")
            as_number = None
            as_name = None
            
            if as_info:
                parts = as_info.split(" ", 1)
                if len(parts) >= 1:
                    as_number = parts[0]
                if len(parts) >= 2:
                    as_name = parts[1]
            
            return {
                "as_number": as_number,
                "as_name": as_name,
                "as_full": as_info,
                "isp": data.get("isp"),
                "org": data.get("org"),
                "query": data.get("query"),
                "status": data.get("status"),
            }
        except Exception as e:
            return {"error": f"IP-API ASN lookup failed: {str(e)}"}
    
    def _lookup_ipinfo(self, ip_address: str) -> Dict[str, Any]:
        """Look up using ipinfo.io service."""
        try:
            url = f"{self.base_urls['ipinfo']}{ip_address}/json"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            
            asn_info = data.get("asn", {})
            as_number = None
            as_name = None
            
            if isinstance(asn_info, dict):
                as_number = asn_info.get("asn")
                as_name = asn_info.get("name")
            elif isinstance(asn_info, str):
                parts = asn_info.split(" ", 1)
                if len(parts) >= 1:
                    as_number = parts[0]
                if len(parts) >= 2:
                    as_name = parts[1]
            
            return {
                "as_number": as_number,
                "as_name": as_name,
                "as_full": asn_info,
                "org": data.get("org"),
                "ip": data.get("ip"),
            }
        except Exception as e:
            return {"error": f"IPInfo ASN lookup failed: {str(e)}"}
    
    def _lookup_hackertarget(self, ip_address: str) -> Dict[str, Any]:
        """Look up using hackertarget.com service."""
        try:
            url = f"{self.base_urls['hackertarget']}?q={ip_address}"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            lines = response.text.strip().split('\n')
            if lines and not lines[0].startswith('error'):
                parts = lines[0].split(',')
                if len(parts) >= 3:
                    return {
                        "ip": parts[0],
                        "as_number": parts[1],
                        "as_name": parts[2],
                        "as_full": f"{parts[1]} {parts[2]}",
                    }
            
            return {"error": "No ASN information found"}
        except Exception as e:
            return {"error": f"HackerTarget ASN lookup failed: {str(e)}"}
    
    def get_as_number(self, ip_address: str) -> Optional[str]:
        """Get AS number for IP address."""
        result = self.lookup(ip_address)
        return result.get("as_number")
    
    def get_as_name(self, ip_address: str) -> Optional[str]:
        """Get AS name for IP address."""
        result = self.lookup(ip_address)
        return result.get("as_name")
    
    def get_isp(self, ip_address: str) -> Optional[str]:
        """Get ISP for IP address."""
        result = self.lookup(ip_address)
        return result.get("isp") or result.get("org")
    
    def get_asn_networks(self, as_number: str) -> Dict[str, Any]:
        """
        Get IP networks (CIDR blocks) owned by an ASN.
        
        Args:
            as_number: AS number (e.g., "AS9318" or "9318")
            
        Returns:
            Dictionary with ASN network information
        """
        try:
            if as_number.startswith("AS"):
                as_number = as_number[2:]
            url = f"https://bgp.he.net/AS{as_number}#_prefixes"

            return self._get_asn_networks_ipinfo(as_number)
            
        except Exception as e:
            return {"error": f"Failed to get ASN networks: {str(e)}"}
    
    def _get_asn_networks_ipinfo(self, as_number: str) -> Dict[str, Any]:
        """Get ASN networks using multiple sources."""
        try:
            sources = [
                self._try_ripe_stat(as_number),
                self._try_bgpview(as_number),
                self._try_he_bgp(as_number)
            ]
            
            for result in sources:
                if "error" not in result:
                    return result
            
            return {
                "as_number": f"AS{as_number}",
                "as_name": "Unknown",
                "networks": [],
                "total_networks": 0,
                "source": "multiple_sources_failed",
                "note": "Could not retrieve ASN network information from available sources"
            }
            
        except Exception as e:
            return {"error": f"ASN networks lookup failed: {str(e)}"}
    
    def _try_ripe_stat(self, as_number: str) -> Dict[str, Any]:
        """Try RIPE Stat API for ASN networks."""
        try:
            url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{as_number}"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            networks = []
            
            if "data" in data and "prefixes" in data["data"]:
                for prefix_info in data["data"]["prefixes"]:
                    if "prefix" in prefix_info:
                        networks.append(prefix_info["prefix"])
            
            return {
                "as_number": f"AS{as_number}",
                "as_name": "Unknown",
                "networks": networks,
                "total_networks": len(networks),
                "source": "ripe_stat"
            }
            
        except Exception as e:
            return {"error": f"RIPE Stat lookup failed: {str(e)}"}
    
    def _try_bgpview(self, as_number: str) -> Dict[str, Any]:
        """Try BGPView API for ASN networks."""
        try:
            url = f"https://api.bgpview.io/asn/{as_number}/prefixes"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            networks = []
            
            if "data" in data and "ipv4_prefixes" in data["data"]:
                for prefix in data["data"]["ipv4_prefixes"]:
                    if "ip" in prefix and "cidr" in prefix:
                        networks.append(f"{prefix['ip']}/{prefix['cidr']}")
            
            return {
                "as_number": f"AS{as_number}",
                "as_name": data.get("data", {}).get("name", "Unknown"),
                "networks": networks,
                "total_networks": len(networks),
                "source": "bgpview"
            }
            
        except Exception as e:
            return {"error": f"BGPView lookup failed: {str(e)}"}
    
    def _try_he_bgp(self, as_number: str) -> Dict[str, Any]:
        """Try Hurricane Electric BGP Toolkit (placeholder)."""
        return {
            "as_number": f"AS{as_number}",
            "as_name": "Unknown",
            "networks": [],
            "total_networks": 0,
            "source": "he_bgp_placeholder",
            "note": "Hurricane Electric BGP Toolkit requires HTML parsing"
        }
    
    def find_ip_network(self, ip_address: str, networks: List[str]) -> Optional[str]:
        """
        Find the specific network that contains the given IP address.
        
        Args:
            ip_address: IP address to find
            networks: List of network CIDR blocks
            
        Returns:
            The network CIDR that contains the IP, or None if not found
        """
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            
            for network_str in networks:
                try:
                    network = ipaddress.ip_network(network_str, strict=False)
                    if ip_obj in network:
                        return network_str
                except ValueError:
                    continue
            
            return None
            
        except Exception:
            return None
    
    def get_network_info_for_public_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Get network information for a public IP using ASN data.
        
        Args:
            ip_address: Public IP address
            
        Returns:
            Dictionary with network information based on ASN
        """
        try:
            asn_info = self.lookup(ip_address)
            as_number = asn_info.get("as_number")
            
            if not as_number:
                return {
                    "error": "Could not determine ASN for this IP",
                    "ip_address": ip_address,
                    "is_private": False,
                    "ip_type": "Public"
                }
            
            asn_networks = self.get_asn_networks(as_number)
            
            if "error" in asn_networks:
                return {
                    "ip_address": ip_address,
                    "asn": as_number,
                    "asn_name": asn_info.get("as_name"),
                    "is_private": False,
                    "ip_type": "Public",
                    "note": f"ASN {as_number} found but network details unavailable",
                    "asn_networks_error": asn_networks["error"]
                }
            
            all_networks = asn_networks.get("networks", [])
            specific_network = self.find_ip_network(ip_address, all_networks)
            
            if specific_network:
                network_obj = ipaddress.ip_network(specific_network, strict=False)
                
                return {
                    "ip_address": ip_address,
                    "asn": as_number,
                    "asn_name": asn_info.get("as_name"),
                    "network_address": str(network_obj.network_address),
                    "subnet_mask": str(network_obj.netmask),
                    "subnet_mask_cidr": f"/{network_obj.prefixlen}",
                    "broadcast_address": str(network_obj.broadcast_address),
                    "total_addresses": network_obj.num_addresses,
                    "usable_addresses": network_obj.num_addresses - 2,
                    "prefix_length": network_obj.prefixlen,
                    "network_range": specific_network,
                    "is_private": False,
                    "ip_type": "Public",
                    "note": f"IP belongs to {specific_network} in ASN {as_number}",
                    "source": "ASN-based lookup"
                }
            else:
                return {
                    "ip_address": ip_address,
                    "asn": as_number,
                    "asn_name": asn_info.get("as_name"),
                    "is_private": False,
                    "ip_type": "Public",
                    "note": f"IP not found in any specific network of ASN {as_number}",
                    "asn_networks": all_networks,
                    "total_asn_networks": len(all_networks),
                    "source": "ASN-based lookup"
                }
            
        except Exception as e:
            return {"error": f"Failed to get network info for public IP: {str(e)}"}
    
    def is_cloud_provider(self, ip_address: str) -> bool:
        """
        Check if IP belongs to a known cloud provider.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            True if IP belongs to cloud provider
        """
        result = self.lookup(ip_address)
        as_name = result.get("as_name", "").lower()
        isp = result.get("isp", "").lower()
        org = result.get("org", "").lower()
        
        cloud_providers = [
            "amazon", "aws", "google", "microsoft", "azure", "cloudflare",
            "digital ocean", "linode", "vultr", "ovh", "hetzner"
        ]
        
        text_to_check = f"{as_name} {isp} {org}"
        return any(provider in text_to_check for provider in cloud_providers)
