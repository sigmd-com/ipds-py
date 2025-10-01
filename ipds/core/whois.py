"""
WHOIS lookup module for IP addresses.
"""

import socket
import json
import requests
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
        """Look up WHOIS information for IP address using API."""
        try:
            # Use IP-API for WHOIS information
            url = f"http://ip-api.com/json/{ip_address}"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            
            # Extract WHOIS-like information from IP-API response
            return {
                "ip": ip_address,
                "asn": data.get("as", "").split()[0] if data.get("as") else None,
                "asn_cidr": None,
                "asn_country_code": data.get("countryCode"),
                "asn_date": None,
                "asn_description": data.get("as", "").split(" ", 1)[1] if data.get("as") and " " in data.get("as", "") else None,
                "asn_registry": None,
                "nets": None,
                "raw": json.dumps({
                    "domain_name": None,
                    "registrar": None,
                    "registrar_url": None,
                    "reseller": None,
                    "whois_server": None,
                    "referral_url": None,
                    "updated_date": None,
                    "creation_date": None,
                    "expiration_date": None,
                    "name_servers": None,
                    "status": data.get("status"),
                    "emails": ["abuse@iana.org"] if data.get("status") == "success" else None,
                    "dnssec": None,
                    "name": None,
                    "org": data.get("org"),
                    "address": None,
                    "city": data.get("city"),
                    "state": data.get("regionName"),
                    "registrant_postal_code": data.get("zip"),
                    "country": data.get("country")
                }, ensure_ascii=False)
            }
        except Exception as e:
            return {"error": f"IP WHOIS lookup failed: {str(e)}"}
    
    def _lookup_domain(self, domain: str) -> Dict[str, Any]:
        """Look up WHOIS information for domain using API."""
        try:
            # Use a simple domain info API
            url = f"https://api.domainsdb.info/v1/domains/search?domain={domain}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                domains = data.get("domains", [])
                if domains:
                    domain_info = domains[0]
                    return {
                        "domain": domain,
                        "domain_name": domain_info.get("domain"),
                        "registrar": domain_info.get("registrar"),
                        "whois_server": None,
                        "referral_url": None,
                        "updated_date": domain_info.get("updated_date"),
                        "creation_date": domain_info.get("creation_date"),
                        "expiration_date": domain_info.get("expiration_date"),
                        "name_servers": domain_info.get("name_servers"),
                        "status": domain_info.get("status"),
                        "emails": domain_info.get("emails"),
                        "dnssec": domain_info.get("dnssec"),
                        "name": domain_info.get("name"),
                        "org": domain_info.get("org"),
                        "address": domain_info.get("address"),
                        "city": domain_info.get("city"),
                        "state": domain_info.get("state"),
                        "zipcode": domain_info.get("zipcode"),
                        "country": domain_info.get("country"),
                        "raw": json.dumps(domain_info, ensure_ascii=False),
                    }
            
            # Fallback to basic info
            return {
                "domain": domain,
                "domain_name": domain,
                "registrar": None,
                "whois_server": None,
                "referral_url": None,
                "updated_date": None,
                "creation_date": None,
                "expiration_date": None,
                "name_servers": None,
                "status": "unknown",
                "emails": None,
                "dnssec": None,
                "name": None,
                "org": None,
                "address": None,
                "city": None,
                "state": None,
                "zipcode": None,
                "country": None,
                "raw": json.dumps({"domain": domain, "status": "not_found"}, ensure_ascii=False),
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
