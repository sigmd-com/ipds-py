"""
ASN (Autonomous System Number) lookup module.
"""

import requests
import json
from typing import Dict, Any, Optional


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
        """
        Get AS number for IP address.
        
        Args:
            ip_address: IP address to look up
            
        Returns:
            AS number or None if not found
        """
        result = self.lookup(ip_address)
        return result.get("as_number")
    
    def get_as_name(self, ip_address: str) -> Optional[str]:
        """
        Get AS name for IP address.
        
        Args:
            ip_address: IP address to look up
            
        Returns:
            AS name or None if not found
        """
        result = self.lookup(ip_address)
        return result.get("as_name")
    
    def get_isp(self, ip_address: str) -> Optional[str]:
        """
        Get ISP for IP address.
        
        Args:
            ip_address: IP address to look up
            
        Returns:
            ISP name or None if not found
        """
        result = self.lookup(ip_address)
        return result.get("isp") or result.get("org")
    
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
