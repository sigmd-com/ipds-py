#!/usr/bin/env python3
"""
IPDS 네트워크 스캐너 예제
이 스크립트는 IPDS를 사용하여 네트워크를 스캔하고 분석하는 예제입니다.
"""

import sys
import os
import ipaddress
import json
from typing import List, Dict, Any

# IPDS 모듈 import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ipds.core.ip_info import IPInfo
from ipds.utils.validation import IPValidator


class NetworkScanner:
    """네트워크 스캐너 클래스"""
    
    def __init__(self):
        self.validator = IPValidator()
        self.results = []
    
    def scan_network_range(self, network_cidr: str) -> List[Dict[str, Any]]:
        """네트워크 범위 스캔"""
        print(f"네트워크 스캔 시작: {network_cidr}")
        
        try:
            network = ipaddress.ip_network(network_cidr, strict=False)
            print(f"네트워크 정보:")
            print(f"  - 네트워크 주소: {network.network_address}")
            print(f"  - 브로드캐스트: {network.broadcast_address}")
            print(f"  - 총 호스트 수: {network.num_addresses - 2}")
            print(f"  - 서브넷 마스크: {network.netmask}")
            print()
            
            # 첫 10개 IP만 스캔 (예제용)
            hosts = list(network.hosts())[:10]
            
            for i, host in enumerate(hosts, 1):
                ip_str = str(host)
                print(f"스캔 중... ({i}/{len(hosts)}) {ip_str}")
                
                try:
                    ip_info = IPInfo(ip_str)
                    result = {
                        "ip_address": ip_str,
                        "basic_info": ip_info.get_basic_info(),
                        "network_info": ip_info.get_network_info()
                    }
                    self.results.append(result)
                    
                except Exception as e:
                    print(f"  ❌ 오류: {str(e)}")
                    self.results.append({
                        "ip_address": ip_str,
                        "error": str(e)
                    })
            
            return self.results
            
        except Exception as e:
            print(f"❌ 네트워크 스캔 오류: {str(e)}")
            return []
    
    def analyze_network_security(self) -> Dict[str, Any]:
        """네트워크 보안 분석"""
        if not self.results:
            return {"error": "스캔 결과가 없습니다."}
        
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
            
            # IP 유형 분류
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
            
            # 네트워크 유형 분류
            ip_type = network_info.get("ip_type", "Unknown")
            analysis["network_types"][ip_type] = analysis["network_types"].get(ip_type, 0) + 1
            
            # ASN 분포
            asn = network_info.get("asn")
            if asn:
                analysis["asn_distribution"][asn] = analysis["asn_distribution"].get(asn, 0) + 1
        
        return analysis
    
    def generate_report(self, output_file: str = "network_scan_report.json"):
        """스캔 보고서 생성"""
        report = {
            "scan_results": self.results,
            "security_analysis": self.analyze_network_security(),
            "summary": self._generate_summary()
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"✅ 보고서가 {output_file}에 저장되었습니다.")
        return report
    
    def _generate_summary(self) -> Dict[str, Any]:
        """요약 정보 생성"""
        if not self.results:
            return {"error": "스캔 결과가 없습니다."}
        
        successful_scans = [r for r in self.results if "error" not in r]
        
        return {
            "total_ips": len(self.results),
            "successful_scans": len(successful_scans),
            "failed_scans": len(self.results) - len(successful_scans),
            "success_rate": f"{(len(successful_scans) / len(self.results)) * 100:.1f}%"
        }


def main():
    """메인 함수"""
    print("🔍 IPDS 네트워크 스캐너")
    print("=" * 50)
    
    scanner = NetworkScanner()
    
    # 테스트할 네트워크 범위들
    test_networks = [
        "192.168.1.0/24",    # 일반적인 홈 네트워크
        "10.0.0.0/24",       # Class A 프라이빗
        "172.16.0.0/24",     # Class B 프라이빗
    ]
    
    for network in test_networks:
        print(f"\n{'='*60}")
        print(f"네트워크 스캔: {network}")
        print(f"{'='*60}")
        
        # 네트워크 스캔
        results = scanner.scan_network_range(network)
        
        if results:
            # 보안 분석
            analysis = scanner.analyze_network_security()
            
            print(f"\n📊 스캔 결과 요약:")
            print(f"  - 총 스캔된 IP: {analysis['total_scanned']}")
            print(f"  - 프라이빗 IP: {analysis['private_ips']}")
            print(f"  - 공인 IP: {analysis['public_ips']}")
            print(f"  - 루프백 IP: {analysis['loopback_ips']}")
            print(f"  - 멀티캐스트 IP: {analysis['multicast_ips']}")
            print(f"  - 예약된 IP: {analysis['reserved_ips']}")
            print(f"  - 오류: {analysis['error_count']}")
            
            if analysis['asn_distribution']:
                print(f"\n🌐 ASN 분포:")
                for asn, count in analysis['asn_distribution'].items():
                    print(f"  - {asn}: {count}개")
        
        print(f"\n{'-'*60}")
    
    # 최종 보고서 생성
    print(f"\n📋 최종 보고서 생성 중...")
    report = scanner.generate_report("final_network_scan_report.json")
    
    print(f"\n✅ 네트워크 스캔 완료!")
    print(f"📁 보고서: final_network_scan_report.json")


if __name__ == "__main__":
    main()
