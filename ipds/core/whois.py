"""
WHOIS lookup module for IP addresses.
"""

import whois
import socket
from typing import Dict, Any, Optional, Union


class Whois:
    """
    WHOIS lookup for IP addresses and domains.
    """
    
    def __init__(self):
        """Initialize WHOIS service."""
        pass
    
    def lookup(self, target: str) -> Dict[str, Any]:
        """
        Look up WHOIS information for an IP address or domain.
        
        Args:
            target: IP address or domain to look up
            
        Returns:
            Dictionary with WHOIS information
        """
        try:
            if self._is_ip_address(target):
                return self._lookup_ip(target)
            else:
                return self._lookup_domain(target)
        except Exception as e:
            return {"error": f"WHOIS lookup failed: {str(e)}"}
    
    def _is_ip_address(self, target: str) -> bool:
        """Check if target is an IP address."""
        try:
            socket.inet_aton(target)
            return True
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, target)
                return True
            except socket.error:
                return False
    
    def _lookup_ip(self, ip_address: str) -> Dict[str, Any]:
        """Look up WHOIS information for IP address."""
        try:
            w = whois.whois(ip_address)
            
            return {
                "ip": ip_address,
                "asn": getattr(w, 'asn', None),
                "asn_cidr": getattr(w, 'asn_cidr', None),
                "asn_country_code": getattr(w, 'asn_country_code', None),
                "asn_date": getattr(w, 'asn_date', None),
                "asn_description": getattr(w, 'asn_description', None),
                "asn_registry": getattr(w, 'asn_registry', None),
                "nets": getattr(w, 'nets', None),
                "raw": str(w) if w else None,
            }
        except Exception as e:
            return {"error": f"IP WHOIS lookup failed: {str(e)}"}
    
    def _lookup_domain(self, domain: str) -> Dict[str, Any]:
        """Look up WHOIS information for domain."""
        try:
            w = whois.whois(domain)
            
            return {
                "domain": domain,
                "domain_name": getattr(w, 'domain_name', None),
                "registrar": getattr(w, 'registrar', None),
                "whois_server": getattr(w, 'whois_server', None),
                "referral_url": getattr(w, 'referral_url', None),
                "updated_date": getattr(w, 'updated_date', None),
                "creation_date": getattr(w, 'creation_date', None),
                "expiration_date": getattr(w, 'expiration_date', None),
                "name_servers": getattr(w, 'name_servers', None),
                "status": getattr(w, 'status', None),
                "emails": getattr(w, 'emails', None),
                "dnssec": getattr(w, 'dnssec', None),
                "name": getattr(w, 'name', None),
                "org": getattr(w, 'org', None),
                "address": getattr(w, 'address', None),
                "city": getattr(w, 'city', None),
                "state": getattr(w, 'state', None),
                "zipcode": getattr(w, 'zipcode', None),
                "country": getattr(w, 'country', None),
                "raw": str(w) if w else None,
            }
        except Exception as e:
            return {"error": f"Domain WHOIS lookup failed: {str(e)}"}
    
    def get_registrar(self, target: str) -> Optional[str]:
        """
        Get registrar information.
        
        Args:
            target: IP address or domain to look up
            
        Returns:
            Registrar name or None if not found
        """
        result = self.lookup(target)
        return result.get("registrar")
    
    def get_creation_date(self, target: str) -> Optional[Any]:
        """
        Get creation date.
        
        Args:
            target: IP address or domain to look up
            
        Returns:
            Creation date or None if not found
        """
        result = self.lookup(target)
        return result.get("creation_date")
    
    def get_expiration_date(self, target: str) -> Optional[Any]:
        """
        Get expiration date.
        
        Args:
            target: IP address or domain to look up
            
        Returns:
            Expiration date or None if not found
        """
        result = self.lookup(target)
        return result.get("expiration_date")
    
    def get_name_servers(self, target: str) -> Optional[list]:
        """
        Get name servers.
        
        Args:
            target: IP address or domain to look up
            
        Returns:
            List of name servers or None if not found
        """
        result = self.lookup(target)
        return result.get("name_servers")
    
    def is_domain_available(self, domain: str) -> bool:
        """
        Check if domain is available for registration.
        
        Args:
            domain: Domain to check
            
        Returns:
            True if domain is available
        """
        try:
            result = self.lookup(domain)
            return "error" in result or result.get("domain_name") is None
        except:
            return True
