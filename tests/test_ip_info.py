"""
Tests for IPInfo class.
"""

import pytest
from ipds.core.ip_info import IPInfo
from ipds.utils.validation import IPValidator


class TestIPInfo:
    """Test cases for IPInfo class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.validator = IPValidator()
    
    def test_valid_ip_creation(self):
        """Test creating IPInfo with valid IP addresses."""
        valid_ips = ["8.8.8.8", "192.168.1.1", "127.0.0.1"]
        
        for ip in valid_ips:
            ip_info = IPInfo(ip)
            assert ip_info.ip_address == ip
    
    def test_invalid_ip_creation(self):
        """Test creating IPInfo with invalid IP addresses."""
        invalid_ips = ["256.1.1.1", "not.an.ip", "192.168.1"]
        
        for ip in invalid_ips:
            with pytest.raises(ValueError):
                IPInfo(ip)
    
    def test_get_basic_info(self):
        """Test getting basic IP information."""
        ip_info = IPInfo("192.168.1.1")
        basic_info = ip_info.get_basic_info()
        
        assert basic_info["version"] == 4
        assert basic_info["is_private"] is True
        assert basic_info["is_global"] is False
        assert basic_info["is_multicast"] is False
        assert basic_info["is_loopback"] is False
        assert basic_info["is_link_local"] is False
        assert basic_info["is_reserved"] is False
        assert basic_info["compressed"] == "192.168.1.1"
        assert basic_info["exploded"] == "192.168.1.1"
    
    def test_get_basic_info_public_ip(self):
        """Test getting basic info for public IP."""
        ip_info = IPInfo("8.8.8.8")
        basic_info = ip_info.get_basic_info()
        
        assert basic_info["version"] == 4
        assert basic_info["is_private"] is False
        assert basic_info["is_global"] is True
        assert basic_info["is_multicast"] is False
        assert basic_info["is_loopback"] is False
        assert basic_info["is_link_local"] is False
        assert basic_info["is_reserved"] is False
    
    def test_get_basic_info_loopback(self):
        """Test getting basic info for loopback IP."""
        ip_info = IPInfo("127.0.0.1")
        basic_info = ip_info.get_basic_info()
        
        assert basic_info["version"] == 4
        assert basic_info["is_private"] is True
        assert basic_info["is_global"] is False
        assert basic_info["is_loopback"] is True
    
    def test_get_network_info_private(self):
        """Test getting network info for private IP."""
        ip_info = IPInfo("192.168.1.1")
        network_info = ip_info.get_network_info()
        
        assert "network" in network_info
        assert "netmask" in network_info
        assert "broadcast" in network_info
        assert "num_addresses" in network_info
        assert "prefixlen" in network_info
    
    def test_get_network_info_public(self):
        """Test getting network info for public IP."""
        ip_info = IPInfo("8.8.8.8")
        network_info = ip_info.get_network_info()
        
        # Public IPs don't have network info in our implementation
        assert "network" in network_info
        assert network_info["network"] == "Unknown"
        assert "note" in network_info
    
    def test_get_all_info_structure(self):
        """Test structure of get_all_info result."""
        ip_info = IPInfo("8.8.8.8")
        all_info = ip_info.get_all_info()
        
        expected_keys = ["ip_address", "basic_info", "geolocation", "asn", "whois"]
        for key in expected_keys:
            assert key in all_info, f"Key {key} should be in all_info"
        
        assert all_info["ip_address"] == "8.8.8.8"
        assert isinstance(all_info["basic_info"], dict)
        assert isinstance(all_info["geolocation"], dict)
        assert isinstance(all_info["asn"], dict)
        assert isinstance(all_info["whois"], dict)
    
    def test_string_representation(self):
        """Test string representation of IPInfo."""
        ip_info = IPInfo("8.8.8.8")
        
        assert str(ip_info) == "IPInfo(8.8.8.8)"
        assert repr(ip_info) == "IPInfo(ip_address='8.8.8.8')"
    
    def test_ipv6_support(self):
        """Test IPv6 IP support."""
        ip_info = IPInfo("2001:db8::1")
        basic_info = ip_info.get_basic_info()
        
        assert basic_info["version"] == 6
        assert basic_info["compressed"] == "2001:db8::1"
        assert basic_info["exploded"] == "2001:0db8:0000:0000:0000:0000:0000:0001"
    
    def test_multicast_ip(self):
        """Test multicast IP handling."""
        ip_info = IPInfo("224.0.0.1")
        basic_info = ip_info.get_basic_info()
        
        assert basic_info["is_multicast"] is True
        assert basic_info["is_private"] is False
        assert basic_info["is_global"] is False
    
    def test_reserved_ip(self):
        """Test reserved IP handling."""
        ip_info = IPInfo("0.0.0.0")
        basic_info = ip_info.get_basic_info()
        
        assert basic_info["is_reserved"] is True
        assert basic_info["is_private"] is False
        assert basic_info["is_global"] is False
