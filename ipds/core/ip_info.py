"""
Main IP information lookup module.
"""

import ipaddress
from typing import Dict, Any, Optional, Union
from .geolocation import Geolocation
from .asn import ASN
from .whois import Whois
from ..utils.validation import IPValidator
from ..utils.conversion import IPConverter


class IPInfo:
    """
    Main class for comprehensive IP information lookup.
    """
    
    def __init__(self, ip_address: str):
        """
        Initialize IPInfo with an IP address.
        
        Args:
            ip_address: IP address to analyze
        """
        self.ip_address = ip_address
        self.validator = IPValidator()
        self.converter = IPConverter()
        self.geolocation = Geolocation()
        self.asn = ASN()
        self.whois = Whois()
        
        if not self.validator.is_valid(ip_address):
            raise ValueError(f"Invalid IP address: {ip_address}")
    
    def get_all_info(self) -> Dict[str, Any]:
        """
        Get comprehensive information about the IP address.
        
        Returns:
            Dictionary containing all available IP information
        """
        info = {
            "ip_address": self.ip_address,
            "basic_info": self.get_basic_info(),
            "geolocation": self.get_geolocation(),
            "asn": self.get_asn_info(),
            "whois": self.get_whois_info(),
        }
        return info
    
    def get_basic_info(self) -> Dict[str, Any]:
        """
        Get basic IP information.
        
        Returns:
            Dictionary with basic IP information
        """
        ip_obj = ipaddress.ip_address(self.ip_address)
        
        return {
            "version": ip_obj.version,
            "is_private": ip_obj.is_private,
            "is_global": ip_obj.is_global,
            "is_multicast": ip_obj.is_multicast,
            "is_loopback": ip_obj.is_loopback,
            "is_link_local": ip_obj.is_link_local,
            "is_reserved": ip_obj.is_reserved,
            "compressed": ip_obj.compressed,
            "exploded": ip_obj.exploded,
        }
    
    def get_geolocation(self) -> Dict[str, Any]:
        """
        Get geolocation information for the IP address.
        
        Returns:
            Dictionary with geolocation data
        """
        return self.geolocation.lookup(self.ip_address)
    
    def get_asn_info(self) -> Dict[str, Any]:
        """
        Get ASN information for the IP address.
        
        Returns:
            Dictionary with ASN data
        """
        return self.asn.lookup(self.ip_address)
    
    def get_whois_info(self) -> Dict[str, Any]:
        """
        Get WHOIS information for the IP address.
        
        Returns:
            Dictionary with WHOIS data
        """
        return self.whois.lookup(self.ip_address)
    
    def get_network_info(self) -> Dict[str, Any]:
        """
        Get network information for the IP address.
        
        Returns:
            Dictionary with network data
        """
        try:
            if self.validator.is_private(self.ip_address):
                if self.validator.is_class_a_private(self.ip_address):
                    network = ipaddress.IPv4Network("10.0.0.0/8")
                elif self.validator.is_class_b_private(self.ip_address):
                    network = ipaddress.IPv4Network("172.16.0.0/12")
                elif self.validator.is_class_c_private(self.ip_address):
                    network = ipaddress.IPv4Network("192.168.0.0/16")
                else:
                    network = None
            else:
                network = None
            
            if network:
                return {
                    "network": str(network.network_address),
                    "netmask": str(network.netmask),
                    "broadcast": str(network.broadcast_address),
                    "num_addresses": network.num_addresses,
                    "prefixlen": network.prefixlen,
                }
            else:
                return {"network": "Unknown", "note": "Public IP - network info not available"}
                
        except Exception as e:
            return {"error": f"Failed to get network info: {str(e)}"}
    
    def __str__(self) -> str:
        return f"IPInfo({self.ip_address})"
    
    def __repr__(self) -> str:
        return f"IPInfo(ip_address='{self.ip_address}')"
