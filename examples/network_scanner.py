#!/usr/bin/env python3
"""
IPDS Network Scanner Example
This script demonstrates how to use IPDS for network scanning and analysis.
"""

import sys
import os
import ipaddress
import json
from typing import List, Dict, Any

# Import IPDS modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ipds.core.ip_info import IPInfo
from ipds.utils.validation import IPValidator


class NetworkScanner:
    """Network Scanner Class"""
    
    def __init__(self):
        self.validator = IPValidator()
        self.results = []
    
    def scan_network_range(self, network_cidr: str) -> List[Dict[str, Any]]:
        """Scan Network Range"""
        print(f"Starting network scan: {network_cidr}")
        
        try:
            network = ipaddress.ip_network(network_cidr, strict=False)
            print(f"Network Information:")
            print(f"  - Network Address: {network.network_address}")
            print(f"  - Broadcast: {network.broadcast_address}")
            print(f"  - Total Hosts: {network.num_addresses - 2}")
            print(f"  - Subnet Mask: {network.netmask}")
            print()
            
            hosts = list(network.hosts())[:10]
            
            for i, host in enumerate(hosts, 1):
                ip_str = str(host)
                print(f"Scanning... ({i}/{len(hosts)}) {ip_str}")
                
                try:
                    ip_info = IPInfo(ip_str)
                    result = {
                        "ip_address": ip_str,
                        "basic_info": ip_info.get_basic_info(),
                        "network_info": ip_info.get_network_info()
                    }
                    self.results.append(result)
                    
                except Exception as e:
                    print(f"  ❌ Error: {str(e)}")
                    self.results.append({
                        "ip_address": ip_str,
                        "error": str(e)
                    })
            
            return self.results
            
        except Exception as e:
            print(f"❌ Network Scan Error: {str(e)}")
            return []
    
    def analyze_network_security(self) -> Dict[str, Any]:
        """Network Security Analysis"""
        if not self.results:
            return {"error": "No scan results available."}
        
        analysis = {
            "total_scanned": len(self.results),
            "private_ips": 0,
            "public_ips": 0,
            "loopback_ips": 0,
            "multicast_ips": 0,
            "reserved_ips": 0,
            "error_count": 0,
            "network_types": {},
            "asn_distribution": {}
        }
        
        for result in self.results:
            if "error" in result:
                analysis["error_count"] += 1
                continue
            
            basic_info = result.get("basic_info", {})
            network_info = result.get("network_info", {})
            
            # IP type classification
            if basic_info.get("is_private", False):
                analysis["private_ips"] += 1
            elif basic_info.get("is_global", False):
                analysis["public_ips"] += 1
            
            if basic_info.get("is_loopback", False):
                analysis["loopback_ips"] += 1
            
            if basic_info.get("is_multicast", False):
                analysis["multicast_ips"] += 1
            
            if basic_info.get("is_reserved", False):
                analysis["reserved_ips"] += 1
            
            # Network type classification
            ip_type = network_info.get("ip_type", "Unknown")
            analysis["network_types"][ip_type] = analysis["network_types"].get(ip_type, 0) + 1
            
            # ASN distribution
            asn = network_info.get("asn")
            if asn:
                analysis["asn_distribution"][asn] = analysis["asn_distribution"].get(asn, 0) + 1
        
        return analysis
    
    def generate_report(self, output_file: str = "network_scan_report.json"):
        """Generate Scan Report"""
        report = {
            "scan_results": self.results,
            "security_analysis": self.analyze_network_security(),
            "summary": self._generate_summary()
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"✅ Report saved to {output_file}.")
        return report
    
    def _generate_summary(self) -> Dict[str, Any]:
        """Generate Summary Information"""
        if not self.results:
            return {"error": "No scan results available."}
        
        successful_scans = [r for r in self.results if "error" not in r]
        
        return {
            "total_ips": len(self.results),
            "successful_scans": len(successful_scans),
            "failed_scans": len(self.results) - len(successful_scans),
            "success_rate": f"{(len(successful_scans) / len(self.results)) * 100:.1f}%"
        }


def main():
    """Main function"""
    print("IPDS Network Scanner")
    print("=" * 50)
    
    scanner = NetworkScanner()
    
    test_networks = [
        "192.168.1.0/24",    # Common home network
        "10.0.0.0/24",       # Class A private
        "172.16.0.0/24",     # Class B private
    ]
    
    for network in test_networks:
        print(f"\n{'='*60}")
        print(f"Network Scan: {network}")
        print(f"{'='*60}")
        
        results = scanner.scan_network_range(network)
        
        if results:
            analysis = scanner.analyze_network_security()
            
            print(f"\n📊 Scan Results Summary:")
            print(f"  - Total Scanned IPs: {analysis['total_scanned']}")
            print(f"  - Private IPs: {analysis['private_ips']}")
            print(f"  - Public IPs: {analysis['public_ips']}")
            print(f"  - Loopback IPs: {analysis['loopback_ips']}")
            print(f"  - Multicast IPs: {analysis['multicast_ips']}")
            print(f"  - Reserved IPs: {analysis['reserved_ips']}")
            print(f"  - Errors: {analysis['error_count']}")
            
            if analysis['asn_distribution']:
                print(f"\n🌐 ASN Distribution:")
                for asn, count in analysis['asn_distribution'].items():
                    print(f"  - {asn}: {count} IPs")
        
        print(f"\n{'-'*60}")
    
    print(f"\nFinal report generating...")
    report = scanner.generate_report("final_network_scan_report.json")
    
    print(f"\n✅ Network scan completed!")
    print(f"Report: final_network_scan_report.json")


if __name__ == "__main__":
    main()
