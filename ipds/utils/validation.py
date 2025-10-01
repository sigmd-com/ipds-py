"""
IP address validation utilities.
"""

import ipaddress
import re
from typing import Union, List


class IPValidator:
    """
    IP address validation utilities.
    """
    
    def __init__(self):
        """Initialize IP validator."""
        pass
    
    def is_valid(self, ip_address: str) -> bool:
        """
        Check if IP address is valid.
        
        Args:
            ip_address: IP address to validate
            
        Returns:
            True if valid, False otherwise
        """
        try:
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False
    
    def is_ipv4(self, ip_address: str) -> bool:
        """
        Check if IP address is IPv4.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            True if IPv4, False otherwise
        """
        try:
            ipaddress.IPv4Address(ip_address)
            return True
        except ValueError:
            return False
    
    def is_ipv6(self, ip_address: str) -> bool:
        """
        Check if IP address is IPv6.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            True if IPv6, False otherwise
        """
        try:
            ipaddress.IPv6Address(ip_address)
            return True
        except ValueError:
            return False
    
    def is_private(self, ip_address: str) -> bool:
        """
        Check if IP address is private.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            True if private, False otherwise
        """
        try:
            ip = ipaddress.ip_address(ip_address)
            return ip.is_private
        except ValueError:
            return False
    
    def is_public(self, ip_address: str) -> bool:
        """
        Check if IP address is public.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            True if public, False otherwise
        """
        try:
            ip = ipaddress.ip_address(ip_address)
            return ip.is_global
        except ValueError:
            return False
    
    def is_loopback(self, ip_address: str) -> bool:
        """
        Check if IP address is loopback.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            True if loopback, False otherwise
        """
        try:
            ip = ipaddress.ip_address(ip_address)
            return ip.is_loopback
        except ValueError:
            return False
    
    def is_multicast(self, ip_address: str) -> bool:
        """
        Check if IP address is multicast.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            True if multicast, False otherwise
        """
        try:
            ip = ipaddress.ip_address(ip_address)
            return ip.is_multicast
        except ValueError:
            return False
    
    def is_link_local(self, ip_address: str) -> bool:
        """
        Check if IP address is link-local.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            True if link-local, False otherwise
        """
        try:
            ip = ipaddress.ip_address(ip_address)
            return ip.is_link_local
        except ValueError:
            return False
    
    def is_reserved(self, ip_address: str) -> bool:
        """
        Check if IP address is reserved.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            True if reserved, False otherwise
        """
        try:
            ip = ipaddress.ip_address(ip_address)
            return ip.is_reserved
        except ValueError:
            return False
    
    def is_class_a_private(self, ip_address: str) -> bool:
        """
        Check if IP address is in Class A private range (10.0.0.0/8).
        
        Args:
            ip_address: IP address to check
            
        Returns:
            True if Class A private, False otherwise
        """
        try:
            ip = ipaddress.IPv4Address(ip_address)
            return ip in ipaddress.IPv4Network("10.0.0.0/8")
        except ValueError:
            return False
    
    def is_class_b_private(self, ip_address: str) -> bool:
        """
        Check if IP address is in Class B private range (172.16.0.0/12).
        
        Args:
            ip_address: IP address to check
            
        Returns:
            True if Class B private, False otherwise
        """
        try:
            ip = ipaddress.IPv4Address(ip_address)
            return ip in ipaddress.IPv4Network("172.16.0.0/12")
        except ValueError:
            return False
    
    def is_class_c_private(self, ip_address: str) -> bool:
        """
        Check if IP address is in Class C private range (192.168.0.0/16).
        
        Args:
            ip_address: IP address to check
            
        Returns:
            True if Class C private, False otherwise
        """
        try:
            ip = ipaddress.IPv4Address(ip_address)
            return ip in ipaddress.IPv4Network("192.168.0.0/16")
        except ValueError:
            return False
    
    def validate_ip_list(self, ip_list: List[str]) -> dict:
        """
        Validate a list of IP addresses.
        
        Args:
            ip_list: List of IP addresses to validate
            
        Returns:
            Dictionary with validation results
        """
        results = {
            "valid": [],
            "invalid": [],
            "ipv4": [],
            "ipv6": [],
            "private": [],
            "public": [],
        }
        
        for ip in ip_list:
            if self.is_valid(ip):
                results["valid"].append(ip)
                
                if self.is_ipv4(ip):
                    results["ipv4"].append(ip)
                elif self.is_ipv6(ip):
                    results["ipv6"].append(ip)
                
                if self.is_private(ip):
                    results["private"].append(ip)
                elif self.is_public(ip):
                    results["public"].append(ip)
            else:
                results["invalid"].append(ip)
        
        return results
    
    def get_ip_type(self, ip_address: str) -> str:
        """
        Get the type of IP address.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            String describing IP type
        """
        if not self.is_valid(ip_address):
            return "invalid"
        
        if self.is_loopback(ip_address):
            return "loopback"
        elif self.is_private(ip_address):
            return "private"
        elif self.is_multicast(ip_address):
            return "multicast"
        elif self.is_link_local(ip_address):
            return "link_local"
        elif self.is_reserved(ip_address):
            return "reserved"
        elif self.is_public(ip_address):
            return "public"
        else:
            return "unknown"
