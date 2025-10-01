"""
Geolocation lookup module for IP addresses.
"""

import requests
import json
from typing import Dict, Any, Optional


class Geolocation:
    """
    Geolocation lookup for IP addresses.
    """
    
    def __init__(self):
        """Initialize Geolocation service."""
        self.base_urls = {
            "ipapi": "http://ip-api.com/json/",
            "ipinfo": "https://ipinfo.io/",
            "ipgeolocation": "https://api.ipgeolocation.io/ipgeo",
        }
    
    def lookup(self, ip_address: str, service: str = "ipapi") -> Dict[str, Any]:
        """
        Look up geolocation information for an IP address.
        
        Args:
            ip_address: IP address to look up
            service: Service to use for lookup (ipapi, ipinfo, ipgeolocation)
            
        Returns:
            Dictionary with geolocation information
        """
        try:
            if service == "ipapi":
                return self._lookup_ipapi(ip_address)
            elif service == "ipinfo":
                return self._lookup_ipinfo(ip_address)
            elif service == "ipgeolocation":
                return self._lookup_ipgeolocation(ip_address)
            else:
                raise ValueError(f"Unknown service: {service}")
        except Exception as e:
            return {"error": f"Geolocation lookup failed: {str(e)}"}
    
    def _lookup_ipapi(self, ip_address: str) -> Dict[str, Any]:
        """Look up using ip-api.com service."""
        try:
            url = f"{self.base_urls['ipapi']}{ip_address}"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            
            return {
                "country": data.get("country"),
                "country_code": data.get("countryCode"),
                "region": data.get("region"),
                "region_name": data.get("regionName"),
                "city": data.get("city"),
                "zip": data.get("zip"),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "timezone": data.get("timezone"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "as": data.get("as"),
                "query": data.get("query"),
                "status": data.get("status"),
            }
        except Exception as e:
            return {"error": f"IP-API lookup failed: {str(e)}"}
    
    def _lookup_ipinfo(self, ip_address: str) -> Dict[str, Any]:
        """Look up using ipinfo.io service."""
        try:
            url = f"{self.base_urls['ipinfo']}{ip_address}/json"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            
            location = data.get("loc", "").split(",")
            lat = float(location[0]) if len(location) > 0 and location[0] else None
            lon = float(location[1]) if len(location) > 1 and location[1] else None
            
            return {
                "ip": data.get("ip"),
                "city": data.get("city"),
                "region": data.get("region"),
                "country": data.get("country"),
                "loc": data.get("loc"),
                "lat": lat,
                "lon": lon,
                "timezone": data.get("timezone"),
                "org": data.get("org"),
                "postal": data.get("postal"),
                "asn": data.get("asn"),
            }
        except Exception as e:
            return {"error": f"IPInfo lookup failed: {str(e)}"}
    
    def _lookup_ipgeolocation(self, ip_address: str) -> Dict[str, Any]:
        """Look up using ipgeolocation.io service."""
        try:
            url = f"{self.base_urls['ipgeolocation']}?apiKey=free&ip={ip_address}"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            
            return {
                "ip": data.get("ip"),
                "country_name": data.get("country_name"),
                "country_code2": data.get("country_code2"),
                "country_code3": data.get("country_code3"),
                "state_prov": data.get("state_prov"),
                "city": data.get("city"),
                "latitude": data.get("latitude"),
                "longitude": data.get("longitude"),
                "time_zone": data.get("time_zone"),
                "isp": data.get("isp"),
                "organization": data.get("organization"),
                "asn": data.get("asn"),
            }
        except Exception as e:
            return {"error": f"IPGeolocation lookup failed: {str(e)}"}
    
    def get_country(self, ip_address: str) -> Optional[str]:
        """
        Get country for IP address.
        
        Args:
            ip_address: IP address to look up
            
        Returns:
            Country name or None if not found
        """
        result = self.lookup(ip_address)
        return result.get("country") or result.get("country_name")
    
    def get_city(self, ip_address: str) -> Optional[str]:
        """
        Get city for IP address.
        
        Args:
            ip_address: IP address to look up
            
        Returns:
            City name or None if not found
        """
        result = self.lookup(ip_address)
        return result.get("city")
    
    def get_coordinates(self, ip_address: str) -> Optional[tuple]:
        """
        Get coordinates for IP address.
        
        Args:
            ip_address: IP address to look up
            
        Returns:
            Tuple of (latitude, longitude) or None if not found
        """
        result = self.lookup(ip_address)
        lat = result.get("lat") or result.get("latitude")
        lon = result.get("lon") or result.get("longitude")
        
        if lat is not None and lon is not None:
            return (float(lat), float(lon))
        return None
