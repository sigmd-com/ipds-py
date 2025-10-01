#!/usr/bin/env python3
"""
IPDS Python API Usage Examples
This script demonstrates how to use the IPDS Python API.
"""

import sys
import os
import json
from typing import List, Dict, Any

# IPDS 모듈 import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ipds.core.ip_info import IPInfo
from ipds.utils.validation import IPValidator


def basic_ip_analysis():
    """Basic IP Analysis Example"""
    print("=== Basic IP Analysis Example ===")
    
    ip_addresses = [
        "8.8.8.8",      # Google DNS
        "1.1.1.1",      # Cloudflare DNS
        "192.168.1.1",  # Private IP
        "10.0.0.1",     # Private IP
        "127.0.0.1",    # Loopback
        "180.66.201.68" # SK Broadband
    ]
    
    validator = IPValidator()
    
    for ip in ip_addresses:
        print(f"\n--- {ip} Analysis ---")
        
        try:
            # IP validation
            if not validator.is_valid(ip):
                print(f"❌ Invalid IP address: {ip}")
                continue
            
            # Create IPInfo object
            ip_info = IPInfo(ip)
            
            # Get basic information
            basic_info = ip_info.get_basic_info()
            print(f"IP Version: IPv{basic_info['version']}")
            print(f"Private IP: {basic_info['is_private']}")
            print(f"Global IP: {basic_info['is_global']}")
            print(f"Loopback IP: {basic_info['is_loopback']}")
            
            # Get network information
            network_info = ip_info.get_network_info()
            if 'network_range' in network_info:
                print(f"Network Range: {network_info['network_range']}")
                print(f"Subnet Mask: {network_info['subnet_mask']}")
                print(f"Broadcast: {network_info['broadcast_address']}")
            
        except Exception as e:
            print(f"❌ Error occurred: {str(e)}")


def network_analysis():
    """Network Analysis Example"""
    print("\n=== Network Analysis Example ===")
    
    test_ips = {
        "Google DNS": "8.8.8.8",
        "Cloudflare DNS": "1.1.1.1",
        "SK Broadband": "180.66.201.68",
        "Class A Private": "10.0.0.1",
        "Class B Private": "172.16.0.1",
        "Class C Private": "192.168.1.1",
        "Loopback": "127.0.0.1",
        "Link Local": "169.254.1.1"
    }
    
    for name, ip in test_ips.items():
        print(f"\n--- {name} ({ip}) ---")
        
        try:
            ip_info = IPInfo(ip)
            network_info = ip_info.get_network_info()
            
            print(f"IP Type: {network_info.get('ip_type', 'Unknown')}")
            print(f"Private IP: {network_info.get('is_private', 'Unknown')}")
            
            if 'network_range' in network_info:
                print(f"Network Range: {network_info['network_range']}")
                print(f"Subnet Mask: {network_info['subnet_mask']}")
                print(f"CIDR Notation: {network_info['subnet_mask_cidr']}")
                print(f"Total Addresses: {network_info['total_addresses']}")
                print(f"Usable Addresses: {network_info['usable_addresses']}")
            
            if 'asn' in network_info:
                print(f"ASN: {network_info['asn']}")
                print(f"ASN Name: {network_info.get('asn_name', 'Unknown')}")
            
        except Exception as e:
            print(f"❌ Error occurred: {str(e)}")


def batch_processing():
    """Batch Processing Example"""
    print("\n=== Batch Processing Example ===")
    
    # IP list
    ip_list = [
        "8.8.8.8",
        "1.1.1.1", 
        "192.168.1.1",
        "10.0.0.1",
        "180.66.201.68"
    ]
    
    results = []
    
    print(f"Processing {len(ip_list)} IP addresses...")
    
    for i, ip in enumerate(ip_list, 1):
        print(f"Processing... ({i}/{len(ip_list)}) {ip}")
        
        try:
            ip_info = IPInfo(ip)
            
            # Query only necessary information (performance optimization)
            result = {
                "ip_address": ip,
                "basic_info": ip_info.get_basic_info(),
                "network_info": ip_info.get_network_info()
            }
            
            results.append(result)
            
        except Exception as e:
            print(f"❌ Error processing {ip}: {str(e)}")
            results.append({
                "ip_address": ip,
                "error": str(e)
            })
    
    # Save results to JSON file
    output_file = "batch_processing_results.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print(f"\n✅ Batch processing completed! Results saved to {output_file}.")
    
    # Print simple statistics
    private_count = sum(1 for r in results if r.get('basic_info', {}).get('is_private', False))
    public_count = len(results) - private_count
    
    print(f"\n📊 Statistics:")
    print(f"  - Total processed IPs: {len(results)}")
    print(f"  - Private IPs: {private_count}")
    print(f"  - Public IPs: {public_count}")


def custom_analysis():
    """Custom Analysis Example"""
    print("\n=== Custom Analysis Example ===")
    
    def analyze_ip_security(ip: str) -> Dict[str, Any]:
        """IP Security Analysis"""
        try:
            ip_info = IPInfo(ip)
            basic_info = ip_info.get_basic_info()
            network_info = ip_info.get_network_info()
            
            security_analysis = {
                "ip_address": ip,
                "is_private": basic_info["is_private"],
                "is_global": basic_info["is_global"],
                "is_loopback": basic_info["is_loopback"],
                "is_multicast": basic_info["is_multicast"],
                "is_reserved": basic_info["is_reserved"],
                "security_level": "unknown"
            }
            
            # Determine security level
            if basic_info["is_private"]:
                security_analysis["security_level"] = "private"
            elif basic_info["is_loopback"]:
                security_analysis["security_level"] = "loopback"
            elif basic_info["is_multicast"]:
                security_analysis["security_level"] = "multicast"
            elif basic_info["is_reserved"]:
                security_analysis["security_level"] = "reserved"
            else:
                security_analysis["security_level"] = "public"
            
            # Add network information
            if 'network_range' in network_info:
                security_analysis["network_range"] = network_info["network_range"]
                security_analysis["subnet_size"] = network_info["total_addresses"]
            
            return security_analysis
            
        except Exception as e:
            return {
                "ip_address": ip,
                "error": str(e),
                "security_level": "error"
            }
    
    # Test IPs
    test_ips = ["8.8.8.8", "192.168.1.1", "127.0.0.1", "224.0.0.1", "0.0.0.0"]
    
    print("IP Security Analysis Results:")
    for ip in test_ips:
        analysis = analyze_ip_security(ip)
        print(f"\n{ip}:")
        print(f"  Security Level: {analysis['security_level']}")
        print(f"  Private: {analysis.get('is_private', 'N/A')}")
        print(f"  Global: {analysis.get('is_global', 'N/A')}")
        if 'network_range' in analysis:
            print(f"  Network: {analysis['network_range']}")


def main():
    """Main function"""
    print("🚀 IPDS Python API Usage Examples")
    print("=" * 50)
    
    try:
        # Basic IP analysis
        basic_ip_analysis()
        
        # Network analysis
        network_analysis()
        
        # Batch processing
        batch_processing()
        
        # Custom analysis
        custom_analysis()
        
        print("\n✅ All examples completed successfully!")
        
    except KeyboardInterrupt:
        print("\n\n⏹️  Interrupted by user.")
    except Exception as e:
        print(f"\n❌ Unexpected error occurred: {str(e)}")


if __name__ == "__main__":
    main()
