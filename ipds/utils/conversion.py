"""
IP address conversion utilities.
"""

import ipaddress
import struct
import socket
from typing import Union, Optional, Tuple


class IPConverter:
    """
    IP address conversion utilities.
    """
    
    def __init__(self):
        """Initialize IP converter."""
        pass
    
    def ip_to_int(self, ip_address: str) -> int:
        """
        Convert IP address to integer.
        
        Args:
            ip_address: IP address to convert
            
        Returns:
            Integer representation of IP address
        """
        try:
            ip = ipaddress.ip_address(ip_address)
            return int(ip)
        except ValueError as e:
            raise ValueError(f"Invalid IP address: {ip_address}") from e
    
    def int_to_ip(self, ip_int: int, version: int = 4) -> str:
        """
        Convert integer to IP address.
        
        Args:
            ip_int: Integer representation of IP address
            version: IP version (4 or 6)
            
        Returns:
            IP address string
        """
        try:
            if version == 4:
                return str(ipaddress.IPv4Address(ip_int))
            elif version == 6:
                return str(ipaddress.IPv6Address(ip_int))
            else:
                raise ValueError("Version must be 4 or 6")
        except ValueError as e:
            raise ValueError(f"Invalid integer for IP{version}: {ip_int}") from e
    
    def ip_to_bytes(self, ip_address: str) -> bytes:
        """
        Convert IP address to bytes.
        
        Args:
            ip_address: IP address to convert
            
        Returns:
            Bytes representation of IP address
        """
        try:
            ip = ipaddress.ip_address(ip_address)
            return ip.packed
        except ValueError as e:
            raise ValueError(f"Invalid IP address: {ip_address}") from e
    
    def bytes_to_ip(self, ip_bytes: bytes) -> str:
        """
        Convert bytes to IP address.
        
        Args:
            ip_bytes: Bytes representation of IP address
            
        Returns:
            IP address string
        """
        try:
            if len(ip_bytes) == 4:
                return str(ipaddress.IPv4Address(ip_bytes))
            elif len(ip_bytes) == 16:
                return str(ipaddress.IPv6Address(ip_bytes))
            else:
                raise ValueError(f"Invalid bytes length: {len(ip_bytes)}")
        except ValueError as e:
            raise ValueError(f"Invalid bytes for IP address: {ip_bytes}") from e
    
    def ipv4_to_ipv6(self, ipv4_address: str) -> str:
        """
        Convert IPv4 address to IPv6-mapped IPv4 address.
        
        Args:
            ipv4_address: IPv4 address to convert
            
        Returns:
            IPv6-mapped IPv4 address
        """
        try:
            ipv4 = ipaddress.IPv4Address(ipv4_address)
            ipv6 = ipaddress.IPv6Address(f"::ffff:{ipv4}")
            return str(ipv6)
        except ValueError as e:
            raise ValueError(f"Invalid IPv4 address: {ipv4_address}") from e
    
    def ipv6_to_ipv4(self, ipv6_address: str) -> Optional[str]:
        """
        Convert IPv6-mapped IPv4 address to IPv4.
        
        Args:
            ipv6_address: IPv6 address to convert
            
        Returns:
            IPv4 address if convertible, None otherwise
        """
        try:
            ipv6 = ipaddress.IPv6Address(ipv6_address)
            if ipv6.ipv4_mapped:
                return str(ipv6.ipv4_mapped)
            return None
        except ValueError:
            return None
    
    def compress_ipv6(self, ipv6_address: str) -> str:
        """
        Compress IPv6 address.
        
        Args:
            ipv6_address: IPv6 address to compress
            
        Returns:
            Compressed IPv6 address
        """
        try:
            ip = ipaddress.IPv6Address(ipv6_address)
            return ip.compressed
        except ValueError as e:
            raise ValueError(f"Invalid IPv6 address: {ipv6_address}") from e
    
    def expand_ipv6(self, ipv6_address: str) -> str:
        """
        Expand IPv6 address.
        
        Args:
            ipv6_address: IPv6 address to expand
            
        Returns:
            Expanded IPv6 address
        """
        try:
            ip = ipaddress.IPv6Address(ipv6_address)
            return ip.exploded
        except ValueError as e:
            raise ValueError(f"Invalid IPv6 address: {ipv6_address}") from e
    
    def cidr_to_range(self, cidr: str) -> Tuple[str, str]:
        """
        Convert CIDR notation to IP range.
        
        Args:
            cidr: CIDR notation (e.g., "192.168.1.0/24")
            
        Returns:
            Tuple of (first_ip, last_ip)
        """
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            return (str(network.network_address), str(network.broadcast_address))
        except ValueError as e:
            raise ValueError(f"Invalid CIDR notation: {cidr}") from e
    
    def range_to_cidr(self, start_ip: str, end_ip: str) -> str:
        """
        Convert IP range to CIDR notation.
        
        Args:
            start_ip: Starting IP address
            end_ip: Ending IP address
            
        Returns:
            CIDR notation
        """
        try:
            start = ipaddress.ip_address(start_ip)
            end = ipaddress.ip_address(end_ip)
            
            for prefix_len in range(0, 33):
                try:
                    network = ipaddress.ip_network(f"{start}/{prefix_len}", strict=False)
                    if end in network:
                        return str(network)
                except ValueError:
                    continue
            
            return f"{start_ip}-{end_ip}"
        except ValueError as e:
            raise ValueError(f"Invalid IP range: {start_ip}-{end_ip}") from e
    
    def get_network_info(self, cidr: str) -> dict:
        """
        Get network information from CIDR notation.
        
        Args:
            cidr: CIDR notation
            
        Returns:
            Dictionary with network information
        """
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            
            return {
                "network": str(network.network_address),
                "broadcast": str(network.broadcast_address),
                "netmask": str(network.netmask),
                "hostmask": str(network.hostmask),
                "prefixlen": network.prefixlen,
                "num_addresses": network.num_addresses,
                "num_hosts": network.num_addresses - 2 if network.num_addresses > 2 else network.num_addresses,
                "version": network.version,
            }
        except ValueError as e:
            raise ValueError(f"Invalid CIDR notation: {cidr}") from e
    
    def is_ip_in_network(self, ip_address: str, network: str) -> bool:
        """
        Check if IP address is in network.
        
        Args:
            ip_address: IP address to check
            network: Network in CIDR notation
            
        Returns:
            True if IP is in network
        """
        try:
            ip = ipaddress.ip_address(ip_address)
            net = ipaddress.ip_network(network, strict=False)
            return ip in net
        except ValueError:
            return False
