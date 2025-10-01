"""
Tests for IP conversion utilities.
"""

import pytest
from ipds.utils.conversion import IPConverter

class TestIPConverter:
    """Test cases for IPConverter class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.converter = IPConverter()
    
    def test_ip_to_int(self):
        """Test IP to integer conversion."""
        test_cases = [
            ("0.0.0.0", 0),
            ("127.0.0.1", 2130706433),
            ("192.168.1.1", 3232235777),
            ("255.255.255.255", 4294967295),
        ]
        
        for ip, expected_int in test_cases:
            result = self.converter.ip_to_int(ip)
            assert result == expected_int, f"IP {ip} should convert to {expected_int}, got {result}"
    
    def test_int_to_ip(self):
        """Test integer to IP conversion."""
        test_cases = [
            (0, "0.0.0.0"),
            (2130706433, "127.0.0.1"),
            (3232235777, "192.168.1.1"),
            (4294967295, "255.255.255.255"),
        ]
        
        for ip_int, expected_ip in test_cases:
            result = self.converter.int_to_ip(ip_int, version=4)
            assert result == expected_ip, f"Integer {ip_int} should convert to {expected_ip}, got {result}"
    
    def test_ip_to_bytes(self):
        """Test IP to bytes conversion."""
        test_cases = [
            ("192.168.1.1", b'\xc0\xa8\x01\x01'),
            ("127.0.0.1", b'\x7f\x00\x00\x01'),
            ("0.0.0.0", b'\x00\x00\x00\x00'),
        ]
        
        for ip, expected_bytes in test_cases:
            result = self.converter.ip_to_bytes(ip)
            assert result == expected_bytes, f"IP {ip} should convert to {expected_bytes}, got {result}"
    
    def test_bytes_to_ip(self):
        """Test bytes to IP conversion."""
        test_cases = [
            (b'\xc0\xa8\x01\x01', "192.168.1.1"),
            (b'\x7f\x00\x00\x01', "127.0.0.1"),
            (b'\x00\x00\x00\x00', "0.0.0.0"),
        ]
        
        for ip_bytes, expected_ip in test_cases:
            result = self.converter.bytes_to_ip(ip_bytes)
            assert result == expected_ip, f"Bytes {ip_bytes} should convert to {expected_ip}, got {result}"
    
    def test_ipv4_to_ipv6(self):
        """Test IPv4 to IPv6 conversion."""
        test_cases = [
            ("192.168.1.1", "::ffff:192.168.1.1"),
            ("127.0.0.1", "::ffff:127.0.0.1"),
        ]
        
        for ipv4, expected_ipv6 in test_cases:
            result = self.converter.ipv4_to_ipv6(ipv4)
            assert result == expected_ipv6, f"IPv4 {ipv4} should convert to {expected_ipv6}, got {result}"
    
    def test_ipv6_to_ipv4(self):
        """Test IPv6 to IPv4 conversion."""
        test_cases = [
            ("::ffff:192.168.1.1", "192.168.1.1"),
            ("::ffff:127.0.0.1", "127.0.0.1"),
            ("2001:db8::1", None),
        ]
        
        for ipv6, expected_ipv4 in test_cases:
            result = self.converter.ipv6_to_ipv4(ipv6)
            assert result == expected_ipv4, f"IPv6 {ipv6} should convert to {expected_ipv4}, got {result}"
    
    def test_compress_ipv6(self):
        """Test IPv6 compression."""
        test_cases = [
            ("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
            ("2001:0db8:85a3:0000:0000:8a2e:0370:7334", "2001:db8:85a3::8a2e:370:7334"),
        ]
        
        for expanded, expected_compressed in test_cases:
            result = self.converter.compress_ipv6(expanded)
            assert result == expected_compressed, f"IPv6 {expanded} should compress to {expected_compressed}, got {result}"
    
    def test_expand_ipv6(self):
        """Test IPv6 expansion."""
        test_cases = [
            ("2001:db8::1", "2001:0db8:0000:0000:0000:0000:0000:0001"),
            ("::1", "0000:0000:0000:0000:0000:0000:0000:0001"),
        ]
        
        for compressed, expected_expanded in test_cases:
            result = self.converter.expand_ipv6(compressed)
            assert result == expected_expanded, f"IPv6 {compressed} should expand to {expected_expanded}, got {result}"
    
    def test_cidr_to_range(self):
        """Test CIDR to range conversion."""
        test_cases = [
            ("192.168.1.0/24", ("192.168.1.0", "192.168.1.255")),
            ("10.0.0.0/8", ("10.0.0.0", "10.255.255.255")),
            ("172.16.0.0/12", ("172.16.0.0", "172.31.255.255")),
        ]
        
        for cidr, (expected_start, expected_end) in test_cases:
            result = self.converter.cidr_to_range(cidr)
            assert result == (expected_start, expected_end), f"CIDR {cidr} should convert to {expected_start}-{expected_end}, got {result}"
    
    def test_get_network_info(self):
        """Test network information extraction."""
        cidr = "192.168.1.0/24"
        result = self.converter.get_network_info(cidr)
        
        assert result["network"] == "192.168.1.0"
        assert result["broadcast"] == "192.168.1.255"
        assert result["netmask"] == "255.255.255.0"
        assert result["prefixlen"] == 24
        assert result["num_addresses"] == 256
        assert result["version"] == 4
    
    def test_is_ip_in_network(self):
        """Test IP in network checking."""
        test_cases = [
            ("192.168.1.1", "192.168.1.0/24", True),
            ("192.168.2.1", "192.168.1.0/24", False),
            ("10.0.0.1", "10.0.0.0/8", True),
            ("11.0.0.1", "10.0.0.0/8", False),
        ]
        
        for ip, network, expected in test_cases:
            result = self.converter.is_ip_in_network(ip, network)
            assert result == expected, f"IP {ip} in network {network} should be {expected}, got {result}"
    
    def test_invalid_inputs(self):
        """Test invalid input handling."""
        with pytest.raises(ValueError):
            self.converter.ip_to_int("256.1.1.1")
        
        with pytest.raises(ValueError):
            self.converter.int_to_ip(-1, version=4)
        
        with pytest.raises(ValueError):
            self.converter.int_to_ip(2**32, version=4)
        
        with pytest.raises(ValueError):
            self.converter.bytes_to_ip(b'\x00\x00\x00')
        
        with pytest.raises(ValueError):
            self.converter.cidr_to_range("invalid")
        
        with pytest.raises(ValueError):
            self.converter.get_network_info("invalid")
