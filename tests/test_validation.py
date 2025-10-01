"""
Tests for IP validation utilities.
"""

import pytest
from ipds.utils.validation import IPValidator


class TestIPValidator:
    """Test cases for IPValidator class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.validator = IPValidator()
    
    def test_valid_ipv4(self):
        """Test valid IPv4 addresses."""
        valid_ips = [
            "192.168.1.1",
            "8.8.8.8",
            "127.0.0.1",
            "0.0.0.0",
            "255.255.255.255",
        ]
        
        for ip in valid_ips:
            assert self.validator.is_valid(ip), f"IP {ip} should be valid"
            assert self.validator.is_ipv4(ip), f"IP {ip} should be IPv4"
            assert not self.validator.is_ipv6(ip), f"IP {ip} should not be IPv6"
    
    def test_valid_ipv6(self):
        """Test valid IPv6 addresses."""
        valid_ips = [
            "2001:db8::1",
            "::1",
            "::",
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "2001:db8:85a3::8a2e:370:7334",
        ]
        
        for ip in valid_ips:
            assert self.validator.is_valid(ip), f"IP {ip} should be valid"
            assert self.validator.is_ipv6(ip), f"IP {ip} should be IPv6"
            assert not self.validator.is_ipv4(ip), f"IP {ip} should not be IPv4"
    
    def test_invalid_ips(self):
        """Test invalid IP addresses."""
        invalid_ips = [
            "256.1.1.1",
            "192.168.1",
            "192.168.1.1.1",
            "not.an.ip",
            "192.168.1.1/24",
            "2001:db8::gggg",
            "",
            " ",
        ]
        
        for ip in invalid_ips:
            assert not self.validator.is_valid(ip), f"IP {ip} should be invalid"
    
    def test_private_ips(self):
        """Test private IP detection."""
        private_ips = [
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "127.0.0.1",
        ]
        
        for ip in private_ips:
            assert self.validator.is_private(ip), f"IP {ip} should be private"
            assert not self.validator.is_public(ip), f"IP {ip} should not be public"
    
    def test_public_ips(self):
        """Test public IP detection."""
        public_ips = [
            "8.8.8.8",
            "1.1.1.1",
            "208.67.222.222",
        ]
        
        for ip in public_ips:
            assert self.validator.is_public(ip), f"IP {ip} should be public"
            assert not self.validator.is_private(ip), f"IP {ip} should not be private"
    
    def test_loopback_ips(self):
        """Test loopback IP detection."""
        loopback_ips = [
            "127.0.0.1",
            "::1",
        ]
        
        for ip in loopback_ips:
            assert self.validator.is_loopback(ip), f"IP {ip} should be loopback"
    
    def test_class_private_ranges(self):
        """Test Class A, B, C private range detection."""
        # Class A private
        assert self.validator.is_class_a_private("10.0.0.1")
        assert self.validator.is_class_a_private("10.255.255.255")
        assert not self.validator.is_class_a_private("11.0.0.1")
        
        # Class B private
        assert self.validator.is_class_b_private("172.16.0.1")
        assert self.validator.is_class_b_private("172.31.255.255")
        assert not self.validator.is_class_b_private("172.15.0.1")
        assert not self.validator.is_class_b_private("172.32.0.1")
        
        # Class C private
        assert self.validator.is_class_c_private("192.168.0.1")
        assert self.validator.is_class_c_private("192.168.255.255")
        assert not self.validator.is_class_c_private("192.167.0.1")
        assert not self.validator.is_class_c_private("192.169.0.1")
    
    def test_ip_type_detection(self):
        """Test IP type detection."""
        test_cases = [
            ("8.8.8.8", "public"),
            ("192.168.1.1", "private"),
            ("127.0.0.1", "loopback"),
            ("224.0.0.1", "multicast"),
            ("169.254.1.1", "link_local"),
            ("0.0.0.0", "reserved"),
        ]
        
        for ip, expected_type in test_cases:
            actual_type = self.validator.get_ip_type(ip)
            assert actual_type == expected_type, f"IP {ip} should be {expected_type}, got {actual_type}"
    
    def test_validate_ip_list(self):
        """Test IP list validation."""
        ip_list = [
            "8.8.8.8",
            "192.168.1.1",
            "2001:db8::1",
            "256.1.1.1",
            "not.an.ip",
        ]
        
        results = self.validator.validate_ip_list(ip_list)
        
        assert len(results["valid"]) == 3
        assert len(results["invalid"]) == 2
        assert len(results["ipv4"]) == 2
        assert len(results["ipv6"]) == 1
        assert len(results["private"]) == 1
        assert len(results["public"]) == 1
        
        assert "8.8.8.8" in results["valid"]
        assert "192.168.1.1" in results["valid"]
        assert "2001:db8::1" in results["valid"]
        assert "256.1.1.1" in results["invalid"]
        assert "not.an.ip" in results["invalid"]
